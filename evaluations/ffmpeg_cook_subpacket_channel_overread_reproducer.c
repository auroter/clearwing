#include <stdio.h>

#include "libavutil/intreadwrite.h"

#ifndef COOK_SOURCE
#define COOK_SOURCE "libavcodec/cook.c"
#endif
#include COOK_SOURCE

static void write_stereo_subpacket(uint8_t *dst)
{
    AV_WB32(dst, STEREO);
    AV_WB16(dst + 4, 1536);
    AV_WB16(dst + 6, 1);
    AV_WB32(dst + 8, 0);
    AV_WB16(dst + 12, 0);
    AV_WB16(dst + 14, 0);
}

int main(void)
{
    AVCodecContext avctx = { 0 };
    COOKContext cook = { 0 };
    uint8_t extradata[4 * 16] = { 0 };
    uint8_t packet[16 + AV_INPUT_BUFFER_PADDING_SIZE] = { 0 };
    float **outputs;
    int packet_fill = -1;
    int ret;

    for (int i = 0; i < 4; i++)
        write_stereo_subpacket(extradata + i * 16);

    avctx.priv_data = &cook;
    avctx.extradata = extradata;
    avctx.extradata_size = sizeof(extradata);
    avctx.block_align = 16;
    avctx.sample_rate = 44100;
    avctx.bit_rate = 96000;
    av_channel_layout_default(&avctx.ch_layout, 6);

    ret = cook_decode_init(&avctx);
    fprintf(stderr,
            "declared_channels=6 stereo_subpackets=4 total_subpacket_channels=8 "
            "init_result=%d accepted_subpackets=%d\n",
            ret, cook.num_subpackets);
    if (ret < 0) {
        av_channel_layout_uninit(&avctx.ch_layout);
        return 0;
    }

    outputs = av_calloc(6, sizeof(*outputs));
    if (!outputs)
        return 2;
    for (int i = 0; i < 6; i++) {
        outputs[i] = av_calloc(cook.samples_per_channel, sizeof(**outputs));
        if (!outputs[i])
            return 3;
    }

    cook.subpacket[3].size = sizeof(packet) - AV_INPUT_BUFFER_PADDING_SIZE;
    cook.subpacket[3].bits_per_subpacket =
        (cook.subpacket[3].size * 8) >> cook.subpacket[3].bits_per_subpdiv;
    cook.subpacket[3].ch_idx = 6;
    for (int value = 0; value < 256; value++) {
        memset(packet, value, sizeof(packet) - AV_INPUT_BUFFER_PADDING_SIZE);
        if (decode_subpacket(&cook, &cook.subpacket[3], packet, NULL) == 0) {
            packet_fill = value;
            break;
        }
    }
    if (packet_fill < 0)
        return 4;
    memset(packet, packet_fill, sizeof(packet) - AV_INPUT_BUFFER_PADDING_SIZE);
    fprintf(stderr,
            "decoding_subpacket=3 channel_indices=6,7 output_pointer_count=6 "
            "valid_packet_fill=%d\n",
            packet_fill);
    fflush(stderr);
    ret = decode_subpacket(&cook, &cook.subpacket[3], packet, outputs);
    fprintf(stderr, "decode_result=%d\n", ret);

    for (int i = 0; i < 6; i++)
        av_free(outputs[i]);
    av_free(outputs);
    cook_decode_close(&avctx);
    av_channel_layout_uninit(&avctx.ch_layout);
    return ret < 0;
}
