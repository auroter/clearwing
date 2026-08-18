#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "libavcodec/packet.h"
#include "libavformat/avformat.h"
#include "libavformat/avio.h"
#include "libavutil/dict.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"
#include "libavutil/pixfmt.h"

#define OUTPUT_BUFFER_SIZE 4096

typedef struct OutputProbe {
    int opened;
} OutputProbe;

static int probe_write(void *opaque, const uint8_t *buf, int size)
{
    OutputProbe *probe = opaque;
    volatile uint8_t sample;

    fprintf(stderr,
            "io_callback=%d advertised_size=%d sample_offset=%d\n",
            probe->opened, size, AV_INPUT_BUFFER_PADDING_SIZE + 1);
    fflush(stderr);
    sample = buf[AV_INPUT_BUFFER_PADDING_SIZE + 1];
    return size + (sample & 0);
}

static int open_output(AVFormatContext *format, AVIOContext **io,
                       const char *url, int flags, AVDictionary **options)
{
    OutputProbe *probe = format->opaque;
    uint8_t *buffer = av_malloc(OUTPUT_BUFFER_SIZE);

    (void)url;
    (void)flags;
    (void)options;
    if (!buffer)
        return AVERROR(ENOMEM);
    probe->opened++;
    *io = avio_alloc_context(buffer, OUTPUT_BUFFER_SIZE, 1, probe,
                             NULL, probe_write, NULL);
    if (!*io) {
        av_free(buffer);
        return AVERROR(ENOMEM);
    }
    return 0;
}

static int close_output(AVFormatContext *format, AVIOContext *io)
{
    (void)format;
    avio_context_free(&io);
    return 0;
}

int main(void)
{
    const int width = 46340;
    const int height = 46340;
    const int64_t y_size = (int64_t)width * height;
    const int64_t uv_size = (int64_t)((width + 1) / 2) * ((height + 1) / 2);
    AVFormatContext *format = NULL;
    AVStream *stream = NULL;
    AVPacket *packet = NULL;
    OutputProbe probe = { 0 };
    int header_written = 0;
    int ret = 1;

    if (avformat_alloc_output_context2(
            &format, NULL, "image2", "bounded-output.y") < 0)
        goto done;
    format->opaque = &probe;
    format->io_open = open_output;
    format->io_close2 = close_output;
    stream = avformat_new_stream(format, NULL);
    packet = av_packet_alloc();
    if (!stream || !packet)
        goto done;
    stream->codecpar->codec_type = AVMEDIA_TYPE_VIDEO;
    stream->codecpar->codec_id = AV_CODEC_ID_RAWVIDEO;
    stream->codecpar->format = AV_PIX_FMT_YUV420P;
    stream->codecpar->width = width;
    stream->codecpar->height = height;
    stream->time_base = (AVRational) { 1, 25 };

    if (avformat_write_header(format, NULL) < 0) {
        fprintf(stderr, "header_rejected=1\n");
        goto done;
    }
    header_written = 1;
    if (av_new_packet(packet, 1) < 0)
        goto done;
    packet->data[0] = 0;
    packet->stream_index = stream->index;
    packet->pts = packet->dts = 0;
    packet->duration = 1;

    fprintf(stderr,
            "muxer=image2 split_planes=1 width=%d height=%d "
            "y_size=%" PRId64 " uv_size=%" PRId64
            " true_total=%" PRId64
            " packet_size=1 packet_padding=%d output_io_buffer=%d\n",
            width, height, y_size, uv_size, y_size + 2 * uv_size,
            AV_INPUT_BUFFER_PADDING_SIZE, OUTPUT_BUFFER_SIZE);
    fflush(stderr);
    ret = av_write_frame(format, packet);
    fprintf(stderr, "unexpected_write_return=%d\n", ret);

done:
    av_packet_free(&packet);
    if (format && header_written)
        av_write_trailer(format);
    avformat_free_context(format);
    return ret < 0 ? 3 : ret;
}
