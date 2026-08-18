#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/buffer.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

#include "libavcodec/yuv4enc.c"

#define WIDTH 3
#define HEIGHT 3
#define CHROMA_WIDTH ((WIDTH + 1) / 2)
#define CHROMA_HEIGHT ((HEIGHT + 1) / 2)

static AVFrame *make_tight_frame(void)
{
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->buf[0] = av_buffer_alloc(WIDTH * HEIGHT);
    frame->buf[1] = av_buffer_alloc(CHROMA_WIDTH * CHROMA_HEIGHT);
    frame->buf[2] = av_buffer_alloc(CHROMA_WIDTH * CHROMA_HEIGHT);
    if (!frame->buf[0] || !frame->buf[1] || !frame->buf[2]) {
        av_frame_free(&frame);
        return NULL;
    }

    frame->format = AV_PIX_FMT_YUV420P;
    frame->width = WIDTH;
    frame->height = HEIGHT;
    frame->data[0] = frame->buf[0]->data;
    frame->data[1] = frame->buf[1]->data;
    frame->data[2] = frame->buf[2]->data;
    frame->linesize[0] = WIDTH;
    frame->linesize[1] = CHROMA_WIDTH;
    frame->linesize[2] = CHROMA_WIDTH;
    memset(frame->data[0], 0x10, WIDTH * HEIGHT);
    memset(frame->data[1], 0x80, CHROMA_WIDTH * CHROMA_HEIGHT);
    memset(frame->data[2], 0x80, CHROMA_WIDTH * CHROMA_HEIGHT);
    return frame;
}

int main(void)
{
    const AVCodec *codec = &ff_yuv4_encoder.p;
    AVCodecContext *context = NULL;
    AVFrame *frame = NULL;
    AVPacket *packet = NULL;
    int ret = 1;

    context = avcodec_alloc_context3(codec);
    if (!context)
        goto done;
    context->width = WIDTH;
    context->height = HEIGHT;
    context->pix_fmt = AV_PIX_FMT_YUV420P;
    context->time_base = (AVRational){ 1, 1 };
    if (avcodec_open2(context, codec, NULL) < 0)
        goto done;

    frame = make_tight_frame();
    packet = av_packet_alloc();
    if (!frame || !packet)
        goto done;

    fprintf(stderr,
            "codec=yuv4 width=%d height=%d luma_linesize=%d "
            "luma_buffer_size=%d final_luma_index=%d\n",
            WIDTH, HEIGHT, frame->linesize[0], WIDTH * HEIGHT,
            WIDTH * HEIGHT);
    fflush(stderr);
    ret = avcodec_send_frame(context, frame);
    if (ret >= 0)
        ret = avcodec_receive_packet(context, packet);
    fprintf(stderr, "unexpected_encode_return=%d packet_size=%d\n",
            ret, packet->size);

done:
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return ret < 0 ? 2 : 0;
}
