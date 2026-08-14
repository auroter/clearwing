#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"

#define INPUT_SIZE 85
#define IO_BUFFER_SIZE 4096

typedef struct MemoryInput {
    const uint8_t *data;
    int64_t size;
    int64_t position;
} MemoryInput;

static void write_be16(uint8_t *dst, unsigned value)
{
    dst[0] = value >> 8;
    dst[1] = value;
}

static void write_be32(uint8_t *dst, uint32_t value)
{
    dst[0] = value >> 24;
    dst[1] = value >> 16;
    dst[2] = value >> 8;
    dst[3] = value;
}

static void make_scd_input(uint8_t input[INPUT_SIZE])
{
    memset(input, 0, INPUT_SIZE);
    memcpy(input, "SEDBSSCF", 8);
    write_be32(input + 8, 3);
    write_be16(input + 14, 20);
    write_be32(input + 16, INPUT_SIZE);

    write_be16(input + 22, 1);
    write_be32(input + 28, 48);
    write_be32(input + 32, 48);
    write_be32(input + 36, 48);
    write_be32(input + 48, 52);

    write_be32(input + 52, 1);
    write_be32(input + 56, 0);
    write_be32(input + 60, 48000);
    write_be32(input + 64, 0);
}

static int read_packet(void *opaque, uint8_t *buf, int buf_size)
{
    MemoryInput *input = opaque;
    int64_t remaining = input->size - input->position;
    int amount;

    if (remaining <= 0)
        return AVERROR_EOF;
    amount = remaining < buf_size ? (int)remaining : buf_size;
    memcpy(buf, input->data + input->position, amount);
    input->position += amount;
    return amount;
}

static int64_t seek_input(void *opaque, int64_t offset, int whence)
{
    MemoryInput *input = opaque;
    int64_t position;

    if (whence == AVSEEK_SIZE)
        return input->size;
    switch (whence & ~AVSEEK_FORCE) {
    case SEEK_SET:
        position = offset;
        break;
    case SEEK_CUR:
        position = input->position + offset;
        break;
    case SEEK_END:
        position = input->size + offset;
        break;
    default:
        return AVERROR(EINVAL);
    }
    if (position < 0 || position > input->size)
        return AVERROR(EINVAL);
    input->position = position;
    return position;
}

int main(void)
{
    const AVInputFormat *input_format;
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    AVPacket *packet = NULL;
    uint8_t input_bytes[INPUT_SIZE];
    MemoryInput input = { input_bytes, INPUT_SIZE, 0 };
    uint8_t *io_buffer = NULL;
    int ret = 1;

    make_scd_input(input_bytes);
    input_format = av_find_input_format("scd");
    if (!input_format)
        goto done;
    format = avformat_alloc_context();
    io_buffer = av_malloc(IO_BUFFER_SIZE);
    if (!format || !io_buffer)
        goto done;
    io = avio_alloc_context(io_buffer, IO_BUFFER_SIZE, 0, &input,
                            read_packet, NULL, seek_input);
    if (!io)
        goto done;
    io_buffer = NULL;
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;
    format->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;
    ret = avformat_open_input(&format, NULL, input_format, NULL);
    if (ret < 0 || format->nb_streams != 1)
        goto done;
    packet = av_packet_alloc();
    if (!packet)
        goto done;

    fprintf(stderr,
            "format=scd data_type=pcm track_length=1 channels=%d "
            "block_align=%d\n",
            format->streams[0]->codecpar->ch_layout.nb_channels,
            format->streams[0]->codecpar->block_align);
    fflush(stderr);
    ret = av_read_frame(format, packet);
    fprintf(stderr, "unexpected_read_return=%d\n", ret);

done:
    av_packet_free(&packet);
    avformat_close_input(&format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    return ret < 0 ? 2 : 0;
}
