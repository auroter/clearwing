#include <stdint.h>
#include <stdio.h>

#include <zlib.h>

#include "libavcodec/avcodec.h"
#include "libavcodec/codec_id.h"
#include "libavcodec/packet.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"

int main(void)
{
    const uint8_t rle[] = { 1, 0, 0, 255 };
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_MWSC);
    AVCodecContext *context = NULL;
    AVPacket *packet = NULL;
    AVFrame *frame = NULL;
    uLongf compressed_size = compressBound(sizeof(rle));
    int receive_ret;
    int ret = 1;

    if (!codec) {
        fprintf(stderr, "decoder_missing=1\n");
        return 2;
    }
    context = avcodec_alloc_context3(codec);
    packet = av_packet_alloc();
    frame = av_frame_alloc();
    if (!context || !packet || !frame)
        goto done;

    context->width = 1;
    context->height = 1;
    if (avcodec_open2(context, codec, NULL) < 0 ||
        av_new_packet(packet, compressed_size) < 0) {
        fprintf(stderr, "decoder_setup_failed=1\n");
        goto done;
    }
    if (compress2(packet->data, &compressed_size, rle, sizeof(rle),
                  Z_BEST_SPEED) != Z_OK) {
        fprintf(stderr, "compression_failed=1\n");
        goto done;
    }
    packet->size = compressed_size;

    fprintf(stderr,
            "decoder=mwsc frame=1x1 first_packet=1 rle_fill=1 rle_run=255\n");
    fflush(stderr);
    if (avcodec_send_packet(context, packet) < 0) {
        fprintf(stderr, "packet_rejected_before_decode=1\n");
        goto done;
    }
    receive_ret = avcodec_receive_frame(context, frame);
    fprintf(stderr, "receive_ret=%d got_frame=%d key_frame=%d\n",
            receive_ret, receive_ret == 0,
            receive_ret == 0 && !!(frame->flags & AV_FRAME_FLAG_KEY));
    ret = receive_ret == 0 ? 0 : 3;

done:
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&context);
    return ret;
}
