#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/frame.h"

#define PACKET_SIZE 50

int main(void)
{
    static const uint8_t header[] = {
        0x41, 0x04, 0x04, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x14, 0x00, 0x00,
    };
    const AVCodec *codec = avcodec_find_decoder(AV_CODEC_ID_TRUEMOTION2RT);
    AVCodecContext *context = NULL;
    AVFrame *frame = NULL;
    AVPacket *packet = NULL;
    int ret = 1;

    if (!codec)
        goto done;
    context = avcodec_alloc_context3(codec);
    frame = av_frame_alloc();
    packet = av_packet_alloc();
    if (!context || !frame || !packet || av_new_packet(packet, PACKET_SIZE) < 0)
        goto done;

    memset(packet->data, 0, packet->size);
    memcpy(packet->data, header, sizeof(header));
    fprintf(stderr,
            "decoder=truemotion2rt safe_bitstream_reader=0 packet_size=50 "
            "header_offset=10 payload_bytes=40 width=20 height=20 "
            "delta_bits=4 luma_bits=1600 guard_limit_bits=1600\n");
    fflush(stderr);

    ret = avcodec_open2(context, codec, NULL);
    if (ret >= 0)
        ret = avcodec_send_packet(context, packet);
    if (ret >= 0)
        ret = avcodec_receive_frame(context, frame);
    fprintf(stderr, "unexpected_decode_return=%d\n", ret);

done:
    av_packet_free(&packet);
    av_frame_free(&frame);
    avcodec_free_context(&context);
    return ret < 0 ? 2 : ret;
}
