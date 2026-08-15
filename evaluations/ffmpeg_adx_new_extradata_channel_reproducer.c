#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/channel_layout.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"

#define ADX_HEADER_SIZE 24
#define ADX_BLOCK_SIZE 18

static void make_adx_header(uint8_t header[ADX_HEADER_SIZE], int channels)
{
    static const uint8_t copyright[] = { '(', 'c', ')', 'C', 'R', 'I' };

    memset(header, 0, ADX_HEADER_SIZE);
    header[0] = 0x80;
    header[2] = 0x00;
    header[3] = 20; /* Stored offset plus four gives a 24-byte header. */
    header[4] = 3;
    header[5] = ADX_BLOCK_SIZE;
    header[6] = 4;
    header[7] = channels;
    header[8] = 0x00;
    header[9] = 0x00;
    header[10] = 0xac;
    header[11] = 0x44; /* 44,100 Hz. */
    header[16] = 0x01;
    header[17] = 0xf4; /* 500 Hz cutoff. */
    memcpy(header + ADX_HEADER_SIZE - sizeof(copyright), copyright,
           sizeof(copyright));
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_ADPCM_ADX);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    uint8_t initial_header[ADX_HEADER_SIZE];
    uint8_t replacement_header[ADX_HEADER_SIZE];
    uint8_t *side_data;
    int ret = 1;

    if (!codec)
        return 2;
    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    make_adx_header(initial_header, 2);
    make_adx_header(replacement_header, 1);
    context->extradata = av_mallocz(ADX_HEADER_SIZE + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!context->extradata)
        goto done;
    memcpy(context->extradata, initial_header, ADX_HEADER_SIZE);
    context->extradata_size = ADX_HEADER_SIZE;

    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, 2 * ADX_BLOCK_SIZE) < 0)
        goto done;
    memset(packet->data, 0, packet->size);
    side_data = av_packet_new_side_data(packet, AV_PKT_DATA_NEW_EXTRADATA,
                                        ADX_HEADER_SIZE);
    if (!side_data)
        goto done;
    memcpy(side_data, replacement_header, ADX_HEADER_SIZE);

    fprintf(stderr,
            "codec=adpcm_adx initial_channels=2 replacement_channels=1 "
            "packet_bytes=%d stale_decode_channels=2 allocated_planes=1\n",
            packet->size);
    fflush(stderr);

    if (avcodec_send_packet(context, packet) < 0)
        goto done;
    ret = avcodec_receive_frame(context, frame);

done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret < 0 ? 1 : 0;
}
