#include <stdint.h>
#include <stdio.h>

#include "libavcodec/codec_id.h"
#include "libavcodec/packet.h"
#include "libavformat/avformat.h"
#include "libavformat/avio.h"
#include "libavutil/mem.h"

int main(void)
{
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    AVStream *stream = NULL;
    AVPacket *packet = NULL;
    uint8_t *dynamic_buffer = NULL;
    int header_written = 0;
    int ret = 1;

    if (avformat_alloc_output_context2(&format, NULL, "rtp", NULL) < 0 ||
        avio_open_dyn_buf(&io) < 0) {
        fprintf(stderr, "muxer_setup_failed=1\n");
        goto done;
    }
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;
    format->packet_size = 13;

    stream = avformat_new_stream(format, NULL);
    packet = av_packet_alloc();
    if (!stream || !packet) {
        fprintf(stderr, "allocation_failed=1\n");
        goto done;
    }
    stream->time_base = (AVRational) { 1, 90000 };
    stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codecpar->codec_id = AV_CODEC_ID_H263;
    stream->codecpar->width = 16;
    stream->codecpar->height = 16;

    if (avformat_write_header(format, NULL) < 0) {
        fprintf(stderr, "header_rejected=1\n");
        goto done;
    }
    header_written = 1;
    if (av_new_packet(packet, 4) < 0)
        goto done;
    packet->data[0] = 1;
    packet->data[1] = 2;
    packet->data[2] = 3;
    packet->data[3] = 4;
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 3000;

    fprintf(stderr,
            "muxer=rtp codec=h263 packet_size=13 max_payload_size=1 "
            "h263_payload_size=4 computed_copy_size=-1\n");
    fflush(stderr);
    ret = av_write_frame(format, packet);
    fprintf(stderr, "unexpected_write_return=%d\n", ret);

done:
    av_packet_free(&packet);
    if (header_written)
        av_write_trailer(format);
    if (format && format->pb) {
        avio_close_dyn_buf(format->pb, &dynamic_buffer);
        format->pb = NULL;
    }
    av_free(dynamic_buffer);
    avformat_free_context(format);
    return ret < 0 ? 3 : ret;
}
