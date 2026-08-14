#include <stdint.h>
#include <stdio.h>

#include "libavformat/avformat.h"
#include "libavutil/buffer.h"
#include "libavutil/channel_layout.h"
#include "libavutil/mem.h"

#define RTP_PACKET_SIZE 1472

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

    stream->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    stream->codecpar->codec_id = AV_CODEC_ID_AMR_NB;
    stream->codecpar->sample_rate = 8000;
    av_channel_layout_default(&stream->codecpar->ch_layout, 1);
    stream->time_base = (AVRational){ 1, 8000 };

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
    if (!packet)
        goto done;
    packet->buf = av_buffer_alloc(0);
    if (!packet->buf)
        goto done;
    packet->data = packet->buf->data;
    packet->size = 0;
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 160;

    fprintf(stderr,
            "codec=amr_nb packet_size=0 refcounted=%d data_nonnull=%d\n",
            packet->buf != NULL, packet->data != NULL);
    fflush(stderr);
    ret = av_write_frame(format, packet);
    fprintf(stderr, "unexpected_write_return=%d\n", ret);

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
