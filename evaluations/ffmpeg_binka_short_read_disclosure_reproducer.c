#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/packet.h"
#include "libavformat/avio_internal.h"

static int proof_new_packet(AVPacket *packet, int size);

#ifndef BINKA_SOURCE
#define BINKA_SOURCE "libavformat/binka.c"
#endif
#define av_new_packet proof_new_packet
#include BINKA_SOURCE
#undef av_new_packet

static int proof_new_packet(AVPacket *packet, int size)
{
    int ret = av_new_packet(packet, size);

    if (ret >= 0)
        memset(packet->data, 0xA5, packet->size);
    return ret;
}

int main(void)
{
    uint8_t input[] = {
        0, 0,       /* skipped packet field */
        64, 0,      /* declared payload size */
        0x42,       /* only one payload byte is present */
    };
    AVCodecParameters codec_parameters = {
        .codec_type = AVMEDIA_TYPE_AUDIO,
        .codec_id = AV_CODEC_ID_BINKAUDIO_DCT,
        .sample_rate = 48000,
        .ch_layout.nb_channels = 2,
    };
    AVStream stream = { .codecpar = &codec_parameters };
    AVStream *streams[] = { &stream };
    FFIOContext reader;
    AVFormatContext format_context = {
        .streams = streams,
        .nb_streams = 1,
    };
    AVPacket packet = { 0 };
    int stale_tail_bytes = 0;
    int ret;

    ffio_init_read_context(&reader, input, sizeof(input));
    format_context.pb = &reader.pub;

    ret = binka_read_packet(&format_context, &packet);
    if (ret == 0) {
        for (int i = 5; i < packet.size; i++)
            stale_tail_bytes += packet.data[i] == 0xA5;
    }

    fprintf(stderr,
            "declared_payload=64 available_payload=1 read_result=%d "
            "published_size=%d stale_tail_bytes=%d\n",
            ret, ret == 0 ? packet.size : 0, stale_tail_bytes);

    av_packet_unref(&packet);
    return ret == 0 && stale_tail_bytes == 63 ? 0 : 5;
}
