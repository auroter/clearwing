#include <stdint.h>
#include <stdio.h>

#include "libavcodec/avcodec.h"
#include "libavutil/error.h"

static void print_error(const char *what, int error)
{
    char text[AV_ERROR_MAX_STRING_SIZE];

    av_strerror(error, text, sizeof(text));
    fprintf(stderr, "%s: %s\n", what, text);
}

int main(void)
{
    static const uint8_t payload[] = {
        0x00, 0x04, 0x00, 0x04, /* embedded width and height */
        0x00, 0x00,             /* bitmap flag, zero palette entries */
        0x00, 0x80,             /* palette index zero for one block */
    };
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MVC2);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    int ret = 1;

    if (!codec) {
        fprintf(stderr, "mvc2 decoder unavailable\n");
        return 2;
    }

    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto end;

    context->width = context->coded_width = 4;
    context->height = context->coded_height = 4;
    if ((ret = avcodec_open2(context, codec, NULL)) < 0) {
        print_error("open", ret);
        goto end;
    }
    if ((ret = av_new_packet(packet, sizeof(payload))) < 0)
        goto end;
    for (unsigned i = 0; i < sizeof(payload); i++)
        packet->data[i] = payload[i];

    if ((ret = avcodec_send_packet(context, packet)) < 0) {
        print_error("send", ret);
        goto end;
    }
    if ((ret = avcodec_receive_frame(context, frame)) < 0) {
        print_error("receive", ret);
        goto end;
    }

    printf("pixel=%02x%02x%02x%02x format=%d size=%dx%d\n",
           frame->data[0][0], frame->data[0][1],
           frame->data[0][2], frame->data[0][3],
           frame->format, frame->width, frame->height);
    ret = 0;

end:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret < 0 ? 1 : ret;
}
