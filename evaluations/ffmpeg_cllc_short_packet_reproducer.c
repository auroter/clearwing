#include <stdint.h>
#include <stdio.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/frame.h"

#define WIDTH 64
#define HEIGHT 64
#define PACKET_SIZE ((WIDTH * HEIGHT) / 8)
#define CODE_TABLE_BITS (5 + 9 + 8 + 8)
#define HEADER_BITS (16 + 4 * CODE_TABLE_BITS)
#define DECODE_BITS (WIDTH * HEIGHT * 4)

/* The configured checkout omits this decoder, so compile its production
 * implementation into the public avcodec harness. Exercise FFmpeg's supported
 * --disable-safe-bitstream-reader configuration, where callers must keep every
 * unchecked read inside the packet padding. */
#undef CONFIG_SAFE_BITSTREAM_READER
#define CONFIG_SAFE_BITSTREAM_READER 0
#include "libavcodec/cllc.c"

static void put_bits(uint8_t *buffer, int *position, unsigned int value,
                     int count)
{
    for (int bit = count - 1; bit >= 0; bit--) {
        int offset = *position;
        buffer[offset / 8] |= ((value >> bit) & 1U) << (7 - offset % 8);
        (*position)++;
    }
}

int main(void)
{
    const AVCodec *codec = &ff_cllc_decoder.p;
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    uint8_t swapped[PACKET_SIZE] = { 0 };
    int position = 16;
    int ret = 1;

    /* Four complete one-bit VLC tables. Both one-bit codes yield one, so the
     * alpha symbol is always nonzero and ARGB consumes four bits per pixel. */
    swapped[0] = 3;
    for (int table = 0; table < 4; table++) {
        put_bits(swapped, &position, 1, 5);
        put_bits(swapped, &position, 2, 9);
        put_bits(swapped, &position, 1, 8);
        put_bits(swapped, &position, 1, 8);
    }

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    context->width = WIDTH;
    context->height = HEIGHT;
    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, PACKET_SIZE) < 0)
        goto done;

    /* cllc_decode_frame swaps each 16-bit word before constructing its bit
     * reader. Pair-swap the desired reader input back into the public packet. */
    for (int i = 0; i < PACKET_SIZE; i += 2) {
        packet->data[i] = swapped[i + 1];
        packet->data[i + 1] = swapped[i];
    }

    fprintf(stderr,
            "codec=cllc safe_bitstream_reader=0 coding_type=argb width=%d "
            "height=%d packet_bits=%d "
            "guard_bits=%d header_bits=%d decode_bits=%d\n",
            WIDTH, HEIGHT, PACKET_SIZE * 8, WIDTH * HEIGHT, HEADER_BITS,
            DECODE_BITS);
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
