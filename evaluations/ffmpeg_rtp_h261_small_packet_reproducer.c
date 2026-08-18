#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/mem.h"

#define RTP_PACKET_SIZE 13
#define H261_PACKET_SIZE 8
#define H261_PAYLOAD_HEADER_SIZE 4

static int discard_packet(void *opaque, const uint8_t *buf, int size)
{
    (void)opaque;
    (void)buf;
    return size;
}

int main(void)
{
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    AVPacket *packet = NULL;
    AVStream *stream;
    uint8_t *io_buffer = NULL;
    int ret = 1;

    if (avformat_alloc_output_context2(&format, NULL, "rtp", NULL) < 0)
        goto done;
    stream = avformat_new_stream(format, NULL);
    if (!stream)
        goto done;

    stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codecpar->codec_id = AV_CODEC_ID_H261;
    stream->codecpar->width = 176;
    stream->codecpar->height = 144;
    stream->time_base = (AVRational){ 1, 25 };
    format->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;

    io_buffer = av_malloc(RTP_PACKET_SIZE);
    if (!io_buffer)
        goto done;
    io = avio_alloc_context(
        io_buffer, RTP_PACKET_SIZE, 1, NULL, NULL, discard_packet, NULL
    );
    if (!io)
        goto done;
    io_buffer = NULL;
    io->max_packet_size = RTP_PACKET_SIZE;
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;

    if (avformat_write_header(format, NULL) < 0)
        goto done;
    packet = av_packet_alloc();
    if (!packet || av_new_packet(packet, H261_PACKET_SIZE) < 0)
        goto done;
    memset(packet->data, 0, packet->size);
    packet->data[1] = 1;
    packet->data[2] = 0x80;
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 1;

    fprintf(
        stderr,
        "rtp_packet_size=%d max_payload_size=%d h261_header_size=%d "
        "fragment_size=%d\n",
        RTP_PACKET_SIZE,
        RTP_PACKET_SIZE - 12,
        H261_PAYLOAD_HEADER_SIZE,
        RTP_PACKET_SIZE - 12 - H261_PAYLOAD_HEADER_SIZE
    );
    fflush(stderr);
    ret = av_write_frame(format, packet);
    fprintf(stderr, "write_return=%d\n", ret);

done:
    av_packet_free(&packet);
    if (format)
        av_write_trailer(format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    avformat_free_context(format);
    return ret < 0 ? 2 : 0;
}
