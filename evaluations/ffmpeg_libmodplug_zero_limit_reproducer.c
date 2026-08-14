#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavutil/dict.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"

#define INPUT_SIZE 4096
#define IO_BUFFER_SIZE 4096

typedef struct MemoryInput {
    const uint8_t *data;
    int64_t size;
    int64_t position;
} MemoryInput;

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
    static const uint8_t input_bytes[INPUT_SIZE] = { 0 };
    const AVInputFormat *input_format;
    AVFormatContext *format = NULL;
    AVDictionary *options = NULL;
    AVIOContext *io = NULL;
    MemoryInput input = { input_bytes, INPUT_SIZE, 0 };
    uint8_t *io_buffer = NULL;
    int ret = 1;

    input_format = av_find_input_format("libmodplug");
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
    if (av_dict_set(&options, "max_size", "0", 0) < 0)
        goto done;

    fprintf(stderr,
            "format=libmodplug known_size=%d max_size=0 custom_io=1\n",
            INPUT_SIZE);
    fflush(stderr);
    ret = avformat_open_input(&format, NULL, input_format, &options);
    fprintf(stderr, "unexpected_open_return=%d\n", ret);

done:
    av_dict_free(&options);
    avformat_close_input(&format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    return ret < 0 ? 2 : 0;
}
