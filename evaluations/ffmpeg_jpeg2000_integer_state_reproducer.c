#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef JPEG2000_SOURCE
#define JPEG2000_SOURCE "libavcodec/jpeg2000dec.c"
#endif
#include "libavcodec/mqc.c"
#include "libavcodec/mqcdec.c"
#include "libavcodec/jpeg2000.c"
#include JPEG2000_SOURCE

static const uint8_t ppm_first_packet[] = {
    0xff, 0x4f,
    0xff, 0x60, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xd9,
};

/* A valid one-pixel raw codestream produced by Kakadu 5.2.1. */
static const uint8_t second_packet[] = {
    0xff, 0x4f, 0xff, 0x51, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x07, 0x01, 0x01, 0x07, 0x01, 0x01,
    0x07, 0x01, 0x01, 0xff, 0x52, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x01,
    0x05, 0x04, 0x04, 0x00, 0x00, 0xff, 0x5c, 0x00, 0x23, 0x22, 0x77, 0x1e,
    0x76, 0xea, 0x76, 0xea, 0x76, 0xbc, 0x6f, 0x00, 0x6f, 0x00, 0x6e, 0xe2,
    0x67, 0x4c, 0x67, 0x4c, 0x67, 0x64, 0x50, 0x03, 0x50, 0x03, 0x50, 0x45,
    0x57, 0xd2, 0x57, 0xd2, 0x57, 0x61, 0xff, 0x64, 0x00, 0x11, 0x00, 0x01,
    0x4b, 0x61, 0x6b, 0x61, 0x64, 0x75, 0x2d, 0x76, 0x35, 0x2e, 0x32, 0x2e,
    0x31, 0xff, 0x90, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00,
    0x01, 0xff, 0x93, 0xc7, 0xd8, 0x04, 0x08, 0x16, 0xc7, 0xd2, 0x08, 0x05,
    0xd6, 0xdf, 0x60, 0x10, 0x04, 0x8e, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0xff, 0xd9,
};

static int run_cleanup_mask(void)
{
    Jpeg2000DecoderContext decoder = { 0 };
    Jpeg2000CodingStyle codsty = { 0 };
    Jpeg2000T1Context t1 = { 0 };
    Jpeg2000Cblk cblk = { 0 };
    AVCodecContext avctx = { 0 };
    uint8_t compressed[8] = { 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
    int result;

    decoder.avctx = &avctx;
    t1.stride = 3;
    cblk.data = compressed;
    cblk.length = 4;
    cblk.npasses = 1;
    cblk.nonzerobits = 1;

    fprintf(stderr,
            "width=1 height=1 nonzerobits=1 M_b=31 roi_shift=0 "
            "source_internal_bpno=-1 cleanup_pass_bpno=0\n");
    fflush(stderr);
    result = decode_cblk(&decoder, &codsty, &t1, &cblk,
                         1, 1, 0, 0, 31);
    fprintf(stderr, "mask_decode_result=%d reconstructed=0x%08x\n",
            result, (unsigned int)t1.data[0]);
    return result < 0;
}

static int run_roi_shift(void)
{
    Jpeg2000DecoderContext decoder = { 0 };
    Jpeg2000CodingStyle codsty = { 0 };
    Jpeg2000T1Context t1 = { 0 };
    Jpeg2000Cblk cblk = { 0 };
    AVCodecContext avctx = { 0 };
    uint8_t compressed[8] = { 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff };
    int result;

    decoder.avctx = &avctx;
    t1.stride = 3;
    cblk.data = compressed;
    cblk.length = 4;
    cblk.npasses = 1;
    cblk.nonzerobits = 1;

    fprintf(stderr,
            "compressed_byte=0 width=1 height=1 nonzerobits=1 "
            "M_b=0 roi_shift=1 initial_bpno=29\n");
    fflush(stderr);
    result = decode_cblk(&decoder, &codsty, &t1, &cblk,
                         1, 1, 0, 1, 0);
    fprintf(stderr, "roi_decode_result=%d reconstructed=0x%08x\n",
            result, (unsigned int)t1.data[0]);
    return result < 0;
}

static int run_cleanup_two_frame(void)
{
    const AVCodec *codec = &ff_jpeg2000_decoder.p;
    AVCodecContext *context = avcodec_alloc_context3(codec);
    AVPacket *packet = av_packet_alloc();
    AVFrame *frame = av_frame_alloc();
    Jpeg2000DecoderContext *decoder;
    int first_send;
    int first_receive;
    int second_send;
    int second_receive;

    if (!context || !packet || !frame)
        return 2;
    if (avcodec_open2(context, codec, NULL) < 0)
        return 3;
    decoder = context->priv_data;

    if (av_new_packet(packet, sizeof(ppm_first_packet)) < 0)
        return 4;
    memcpy(packet->data, ppm_first_packet, sizeof(ppm_first_packet));
    first_send = avcodec_send_packet(context, packet);
    first_receive = first_send < 0 ? first_send :
                    avcodec_receive_frame(context, frame);
    fprintf(stderr,
            "first_ppm_send=%d first_ppm_receive=%d post_first_has_ppm=%d "
            "post_first_packed_headers_null=%d\n",
            first_send, first_receive, decoder->has_ppm,
            decoder->packed_headers == NULL);
    av_packet_unref(packet);
    av_frame_unref(frame);

    if (av_new_packet(packet, sizeof(second_packet)) < 0)
        return 5;
    memcpy(packet->data, second_packet, sizeof(second_packet));
    fflush(stderr);
    second_send = avcodec_send_packet(context, packet);
    second_receive = second_send < 0 ? second_send :
                     avcodec_receive_frame(context, frame);
    fprintf(stderr,
            "second_send=%d second_receive=%d width=%d height=%d format=%d\n",
            second_send, second_receive, frame->width, frame->height,
            frame->format);
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return second_receive < 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (!strcmp(argv[1], "cleanup-mask"))
        return run_cleanup_mask();
    if (!strcmp(argv[1], "roi-shift"))
        return run_roi_shift();
    if (!strcmp(argv[1], "cleanup-two-frame"))
        return run_cleanup_two_frame();
    return 2;
}
