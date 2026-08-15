#include <stdio.h>
#include <string.h>

#include "libavcodec/sbc.c"
#include "libavcodec/sbcdsp.c"
#include "libavcodec/sbcenc.c"

#define MARKER 0xA5

static int marker_get_encode_buffer(AVCodecContext *avctx, AVPacket *packet,
                                    int flags)
{
    int ret = avcodec_default_get_encode_buffer(avctx, packet, flags);

    if (ret >= 0)
        memset(packet->data, MARKER, packet->size);
    return ret;
}

int main(void)
{
    AVCodecContext *avctx = avcodec_alloc_context3(&ff_sbc_encoder.p);
    AVFrame *frame = av_frame_alloc();
    AVPacket *packet = av_packet_alloc();
    SBCEncContext *sbc;
    int marker_count = 0;
    int limit;
    int ret;

    if (!avctx || !frame || !packet)
        return 2;

    avctx->sample_rate = 44100;
    avctx->sample_fmt = AV_SAMPLE_FMT_S16;
    avctx->bit_rate = 100000;
    av_channel_layout_default(&avctx->ch_layout, 2);
    avctx->get_encode_buffer = marker_get_encode_buffer;
    if (av_opt_set_int(avctx->priv_data, "sbc_delay", 1000, 0) < 0)
        return 3;
    if (avcodec_open2(avctx, &ff_sbc_encoder.p, NULL) < 0)
        return 4;

    sbc = avctx->priv_data;
    limit = sbc->frame.subbands <<
            (4 + (sbc->frame.mode == STEREO ||
                  sbc->frame.mode == JOINT_STEREO));
    frame->format = avctx->sample_fmt;
    frame->sample_rate = avctx->sample_rate;
    frame->nb_samples = avctx->frame_size;
    if (av_channel_layout_copy(&frame->ch_layout, &avctx->ch_layout) < 0 ||
        av_frame_get_buffer(frame, 0) < 0)
        return 5;

    fprintf(stderr,
            "bitpool=%d maximum=%d frame_size=%d samples=%d marker=0xA5\n",
            sbc->frame.bitpool, limit, avctx->frame_size, frame->nb_samples);
    ret = avcodec_send_frame(avctx, frame);
    if (ret < 0)
        return 6;
    ret = avcodec_receive_packet(avctx, packet);
    if (ret < 0)
        return 7;

    for (int i = 3; i < packet->size; i++)
        marker_count += packet->data[i] == MARKER;
    fprintf(stderr,
            "packet_size=%d initialized_header_bytes=3 marker_tail_bytes=%d "
            "got_packet=1\n",
            packet->size, marker_count);

    return sbc->frame.bitpool > limit &&
           packet->size > 3 && marker_count == packet->size - 3 ? 0 : 8;
}
