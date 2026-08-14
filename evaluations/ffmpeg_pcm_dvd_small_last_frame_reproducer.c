#include <stdint.h>
#include <stdio.h>

#include "libavcodec/avcodec.h"
#include "libavutil/buffer.h"
#include "libavutil/channel_layout.h"
#include "libavutil/frame.h"
#include "libavutil/samplefmt.h"

#define CHANNELS 6
#define NB_SAMPLES 1
#define INPUT_BYTES (CHANNELS * NB_SAMPLES * (int)sizeof(int32_t))

static AVFrame *make_tight_frame(void)
{
    AVChannelLayout layout = AV_CHANNEL_LAYOUT_5POINT1;
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->buf[0] = av_buffer_alloc(INPUT_BYTES);
    if (!frame->buf[0]) {
        av_frame_free(&frame);
        return NULL;
    }
    frame->format = AV_SAMPLE_FMT_S32;
    frame->sample_rate = 48000;
    frame->nb_samples = NB_SAMPLES;
    frame->pts = 0;
    if (av_channel_layout_copy(&frame->ch_layout, &layout) < 0) {
        av_frame_free(&frame);
        return NULL;
    }
    frame->data[0] = frame->buf[0]->data;
    frame->extended_data = frame->data;
    for (int i = 0; i < CHANNELS; i++)
        ((int32_t *)frame->data[0])[i] = i << 24;
    return frame;
}

int main(void)
{
    const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_PCM_DVD);
    AVCodecContext *context = NULL;
    AVFrame *frame = NULL;
    AVPacket *packet = NULL;
    AVChannelLayout layout = AV_CHANNEL_LAYOUT_5POINT1;
    int ret = 1;

    if (!codec)
        goto done;
    context = avcodec_alloc_context3(codec);
    if (!context)
        goto done;
    context->sample_fmt = AV_SAMPLE_FMT_S32;
    context->sample_rate = 48000;
    context->time_base = (AVRational){ 1, 48000 };
    if (av_channel_layout_copy(&context->ch_layout, &layout) < 0 ||
        avcodec_open2(context, codec, NULL) < 0)
        goto done;

    frame = make_tight_frame();
    packet = av_packet_alloc();
    if (!frame || !packet)
        goto done;

    fprintf(stderr,
            "codec=pcm_dvd sample_fmt=s32 channels=6 nb_samples=1 "
            "input_bytes=%d frame_size=%d small_last_frame=%d\n",
            INPUT_BYTES, context->frame_size,
            !!(codec->capabilities & AV_CODEC_CAP_SMALL_LAST_FRAME));
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
