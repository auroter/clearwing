#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"
#include "libavutil/buffer.h"
#include "libavutil/frame.h"
#include "libavutil/mem.h"

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#ifndef LIBCODEC2_SOURCE
#define LIBCODEC2_SOURCE "libavcodec/libcodec2.c"
#endif
#include LIBCODEC2_SOURCE

#define CODEC2_FRAME_SAMPLES 320
#define CODEC2_BLOCK_ALIGN 8
#define COMPLETE_FRAMES 13421773
#define CLAIMED_PACKET_SIZE (COMPLETE_FRAMES * CODEC2_BLOCK_ALIGN)

struct CODEC2 {
    int mode;
};

struct CODEC2 *codec2_create(int mode)
{
    struct CODEC2 *codec = malloc(sizeof(*codec));

    if (codec)
        codec->mode = mode;
    return codec;
}

void codec2_destroy(struct CODEC2 *codec)
{
    free(codec);
}

int codec2_samples_per_frame(struct CODEC2 *codec)
{
    return CODEC2_FRAME_SAMPLES;
}

int codec2_bits_per_frame(struct CODEC2 *codec)
{
    return CODEC2_BLOCK_ALIGN * 8;
}

void codec2_set_natural_or_gray(struct CODEC2 *codec, int natural_or_gray)
{
}

void codec2_decode(struct CODEC2 *codec, int16_t *speech, const uint8_t *bits)
{
    for (int i = 0; i < CODEC2_FRAME_SAMPLES; i++)
        speech[i] = (int16_t)i;
}

void codec2_encode(struct CODEC2 *codec, uint8_t *bits, const int16_t *speech)
{
}

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
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    Mapping *mapping = NULL;
    uint8_t *data = MAP_FAILED;
    int send_result;
    int receive_result;
    int ret = 1;

    context = avcodec_alloc_context3(&ff_libcodec2_decoder.p);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    mapping = malloc(sizeof(*mapping));
    if (!context || !packet || !frame || !mapping)
        goto done;

    context->extradata = av_mallocz(CODEC2_EXTRADATA_SIZE +
                                    AV_INPUT_BUFFER_PADDING_SIZE);
    if (!context->extradata)
        goto done;
    context->extradata_size = CODEC2_EXTRADATA_SIZE;
    codec2_make_extradata(context->extradata, 4);
    if (avcodec_open2(context, &ff_libcodec2_decoder.p, NULL) < 0)
        goto done;

    mapping->size = (size_t)CLAIMED_PACKET_SIZE + AV_INPUT_BUFFER_PADDING_SIZE;
    data = mmap(NULL, mapping->size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED)
        goto done;
    packet->buf = av_buffer_create(data, mapping->size, unmap_packet, mapping, 0);
    if (!packet->buf)
        goto done;
    packet->data = data;
    packet->size = CLAIMED_PACKET_SIZE;
    data = MAP_FAILED;
    mapping = NULL;

    fprintf(stderr,
            "packet_size=%d block_align=%d nframes=%d frame_size=%d "
            "mathematical_samples=%lld wrapped_samples=%d virtual_mapping=valid\n",
            CLAIMED_PACKET_SIZE, context->block_align, COMPLETE_FRAMES,
            context->frame_size, (long long)COMPLETE_FRAMES * CODEC2_FRAME_SAMPLES,
            (int)((uint32_t)COMPLETE_FRAMES * CODEC2_FRAME_SAMPLES));
    fflush(stderr);

    send_result = avcodec_send_packet(context, packet);
    if (send_result < 0) {
        fprintf(stderr, "send_result=%d\n", send_result);
        ret = send_result == AVERROR_INVALIDDATA ? 0 : 1;
        goto done;
    }
    receive_result = avcodec_receive_frame(context, frame);
    fprintf(stderr, "receive_result=%d nb_samples=%d\n", receive_result,
            frame->nb_samples);
    ret = receive_result >= 0;

done:
    if (data != MAP_FAILED)
        munmap(data, mapping->size);
    free(mapping);
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
