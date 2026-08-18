#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavformat/avio.h"
#include "libavutil/crc.h"
#include "libavutil/error.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mem.h"

#define IO_BUFFER_SIZE 4096
#define REPEAT_PAGE_LIMIT 4096

typedef struct StreamingOggInput {
    uint8_t identification_page[28 + 60];
    uint8_t repeat_page[28 + 8];
    size_t identification_size;
    size_t repeat_size;
    size_t position;
} StreamingOggInput;

static size_t build_page(uint8_t *page, uint8_t flags, uint32_t sequence,
                         const uint8_t *payload, size_t payload_size)
{
    const AVCRC *table = av_crc_get_table(AV_CRC_32_IEEE);
    size_t size = 28 + payload_size;
    uint32_t crc;

    memset(page, 0, size);
    memcpy(page, "OggS", 4);
    page[4] = 0;
    page[5] = flags;
    AV_WL64(page + 6, flags & 2 ? UINT64_MAX : 0);
    AV_WL32(page + 14, 0x43574f47);
    AV_WL32(page + 18, sequence);
    page[26] = 1;
    page[27] = payload_size;
    memcpy(page + 28, payload, payload_size);
    crc = av_crc(table, 0, page, size);
    AV_WB32(page + 22, crc);
    return size;
}

static void initialize_input(StreamingOggInput *input)
{
    uint8_t identification[60] = { 0 };
    uint8_t comment[8] = { 0 };

    memcpy(identification, "CELT    ", 8);
    AV_WL32(identification + 28, 0x80000010);
    AV_WL32(identification + 32, sizeof(identification));
    AV_WL32(identification + 36, 48000);
    AV_WL32(identification + 40, 2);
    AV_WL32(identification + 44, 256);
    AV_WL32(identification + 48, 128);
    AV_WL32(identification + 52, 64);
    AV_WL32(identification + 56, 0x7ffffffe);

    input->identification_size =
        build_page(input->identification_page, 2, 0,
                   identification, sizeof(identification));
    input->repeat_size =
        build_page(input->repeat_page, 0, 1, comment, sizeof(comment));
}

static int read_packet(void *opaque, uint8_t *buf, int buf_size)
{
    StreamingOggInput *input = opaque;
    const size_t total_size =
        input->identification_size + REPEAT_PAGE_LIMIT * input->repeat_size;
    size_t remaining;
    size_t amount;
    size_t copied = 0;

    if (input->position >= total_size)
        return AVERROR(EIO);
    remaining = total_size - input->position;
    amount = remaining < (size_t)buf_size ? remaining : (size_t)buf_size;

    while (copied < amount) {
        const uint8_t *source;
        size_t source_size;
        size_t source_offset;
        size_t chunk;

        if (input->position < input->identification_size) {
            source = input->identification_page;
            source_size = input->identification_size;
            source_offset = input->position;
        } else {
            source = input->repeat_page;
            source_size = input->repeat_size;
            source_offset =
                (input->position - input->identification_size) % source_size;
        }
        chunk = source_size - source_offset;
        if (chunk > amount - copied)
            chunk = amount - copied;
        memcpy(buf + copied, source + source_offset, chunk);
        copied += chunk;
        input->position += chunk;
    }
    return amount;
}

int main(void)
{
    const AVInputFormat *input_format = av_find_input_format("ogg");
    StreamingOggInput input = { 0 };
    AVFormatContext *format = NULL;
    AVIOContext *io = NULL;
    uint8_t *io_buffer = NULL;
    size_t repeated_pages = 0;
    int ret = 1;

    if (!input_format) {
        fprintf(stderr, "ogg_demuxer_missing=1\n");
        return 2;
    }
    initialize_input(&input);
    format = avformat_alloc_context();
    io_buffer = av_malloc(IO_BUFFER_SIZE);
    if (!format || !io_buffer)
        goto done;
    io = avio_alloc_context(io_buffer, IO_BUFFER_SIZE, 0, &input,
                            read_packet, NULL, NULL);
    if (!io)
        goto done;
    io_buffer = NULL;
    format->pb = io;
    format->flags |= AVFMT_FLAG_CUSTOM_IO;

    fprintf(stderr,
            "format=ogg codec=celt extra_headers=2147483646 "
            "derived_header_count=2147483647 repeat_page_limit=%d\n",
            REPEAT_PAGE_LIMIT);
    fflush(stderr);
    ret = avformat_open_input(&format, NULL, input_format, NULL);
    repeated_pages =
        input.position > input.identification_size
            ? (input.position - input.identification_size) / input.repeat_size
            : 0;
    fprintf(stderr,
            "open_return=%d bytes_served=%zu repeated_pages=%zu "
            "bounded_reproducer_observed=%d\n",
            ret, input.position, repeated_pages,
            ret == AVERROR(EIO) && repeated_pages == REPEAT_PAGE_LIMIT);

done:
    avformat_close_input(&format);
    if (io)
        avio_context_free(&io);
    else
        av_free(io_buffer);
    return ret == AVERROR(EIO) && repeated_pages == REPEAT_PAGE_LIMIT ? 0 : 3;
}
