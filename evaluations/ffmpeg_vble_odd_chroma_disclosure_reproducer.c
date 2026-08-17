#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/error.h"

static int marker_get_buffer2(AVCodecContext *context, AVFrame *frame, int flags)
{
    int ret = avcodec_default_get_buffer2(context, frame, flags);

    if (ret < 0)
        return ret;
    for (int i = 0; i < AV_NUM_DATA_POINTERS && frame->buf[i]; i++)
        memset(frame->buf[i]->data, 0xA5, frame->buf[i]->size);
    return 0;
}

int main(void)
{
    static const uint8_t payload[] = {
        0x01, 0x00, 0x00, 0x00, /* VBLE version one */
        0xFF, 0xFF, 0xFF,       /* seventeen zero-length symbols */
    };
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_VBLE);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    int ret = 1;

    if (!codec) {
        fprintf(stderr, "vble decoder unavailable\n");
        return 2;
    }

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto end;

    context->width = context->coded_width = 3;
    context->height = context->coded_height = 3;
    context->thread_count = 1;
    context->get_buffer2 = marker_get_buffer2;
    if ((ret = avcodec_open2(context, codec, NULL)) < 0)
        goto end;
    if ((ret = av_new_packet(packet, sizeof(payload))) < 0)
        goto end;
    memcpy(packet->data, payload, sizeof(payload));
    if ((ret = avcodec_send_packet(context, packet)) < 0)
        goto end;
    if ((ret = avcodec_receive_frame(context, frame)) < 0)
        goto end;

    printf("format=%d size=%dx%d linesizes=%d,%d,%d "
           "u=%02x%02x/%02x%02x v=%02x%02x/%02x%02x\n",
           frame->format, frame->width, frame->height,
           frame->linesize[0], frame->linesize[1], frame->linesize[2],
           frame->data[1][0], frame->data[1][1],
           frame->data[1][frame->linesize[1]],
           frame->data[1][frame->linesize[1] + 1],
           frame->data[2][0], frame->data[2][1],
           frame->data[2][frame->linesize[2]],
           frame->data[2][frame->linesize[2] + 1]);
    ret = 0;

end:
    if (ret < 0) {
        char error[AV_ERROR_MAX_STRING_SIZE];

        av_strerror(ret, error, sizeof(error));
        fprintf(stderr, "%s\n", error);
    }
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret < 0 ? 1 : ret;
}
