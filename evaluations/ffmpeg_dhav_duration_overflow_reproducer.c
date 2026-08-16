#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"

#define IO_BUFFER_SIZE 4096
#define VIRTUAL_SIZE INT64_MAX

typedef struct VirtualDHAVInput {
    int64_t position;
} VirtualDHAVInput;

static int read_packet(void *opaque, uint8_t *buf, int buf_size)
{
    static const uint8_t file_header[] = { 'D', 'A', 'H', 'U', 'A' };
    static const uint8_t footer[] = { 'd', 'h', 'a', 'v', 0, 0, 0, 0 };
    VirtualDHAVInput *input = opaque;
    int64_t remaining = VIRTUAL_SIZE - input->position;
    int amount;

    if (remaining <= 0)
        return AVERROR_EOF;
    amount = remaining < buf_size ? (int)remaining : buf_size;
    memset(buf, 0, amount);

    for (int i = 0; i < amount; i++) {
        int64_t position = input->position + i;

        if (position < (int64_t)sizeof(file_header))
            buf[i] = file_header[position];
        if (position >= VIRTUAL_SIZE - (int64_t)sizeof(footer))
            buf[i] = footer[position - (VIRTUAL_SIZE - sizeof(footer))];
    }

    input->position += amount;
    return amount;
}

static int64_t seek_input(void *opaque, int64_t offset, int whence)
{
    VirtualDHAVInput *input = opaque;
    int64_t position;

    if (whence == AVSEEK_SIZE)
        return VIRTUAL_SIZE;

    switch (whence & ~AVSEEK_FORCE) {
    case SEEK_SET:
        position = offset;
        break;
    case SEEK_CUR:
        if ((offset > 0 && input->position > VIRTUAL_SIZE - offset) ||
            (offset < 0 && input->position < -offset))
            return AVERROR(EINVAL);
        position = input->position + offset;
        break;
    case SEEK_END:
        if (offset > 0 || offset < -VIRTUAL_SIZE)
            return AVERROR(EINVAL);
        position = VIRTUAL_SIZE + offset;
        break;
    default:
        return AVERROR(EINVAL);
    }

    if (position < 0 || position > VIRTUAL_SIZE)
        return AVERROR(EINVAL);
    input->position = position;
    return position;
}

int main(void)
{
    const AVInputFormat *input_format;
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    VirtualDHAVInput input = { 0 };
    uint8_t *io_buffer = NULL;
    int ret = 1;

    input_format = av_find_input_format("dhav");
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
    io->seekable = AVIO_SEEKABLE_NORMAL;
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;

    fprintf(stderr,
            "format=dhav virtual_size=%" PRId64
            " duration_buffer=1048576 footer_offset=1048568"
            " seek_back=0 candidate_pos=%" PRId64 "\n",
            (int64_t)VIRTUAL_SIZE, (int64_t)VIRTUAL_SIZE);
    fflush(stderr);

    ret = avformat_open_input(&format, NULL, input_format, NULL);
    fprintf(stderr, "unexpected_open_return=%d\n", ret);

done:
    avformat_close_input(&format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    return ret < 0 ? 2 : 0;
}
