#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avio.h"
#include "libavformat/sox.h"
#include "libavutil/intfloat.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mem.h"

#ifndef SOXDEC_SOURCE
#define SOXDEC_SOURCE "libavformat/soxdec.c"
#endif
#include SOXDEC_SOURCE

typedef struct InputBuffer {
    const uint8_t *data;
    size_t size;
    size_t offset;
} InputBuffer;

static int read_packet(void *opaque, uint8_t *buffer, int buffer_size)
{
    InputBuffer *input = opaque;
    size_t remaining = input->size - input->offset;
    size_t count = FFMIN(remaining, (size_t)buffer_size);

    if (!count)
        return AVERROR_EOF;
    memcpy(buffer, input->data + input->offset, count);
    input->offset += count;
    return (int)count;
}

int main(void)
{
    uint8_t file_data[SOX_FIXED_HDR + 4] = { 0 };
    uint8_t *avio_buffer = NULL;
    InputBuffer input = { file_data, sizeof(file_data), 0 };
    AVFormatContext *format = NULL;
    AVIOContext *avio = NULL;
    int result;

    AV_WL32(file_data, SOX_TAG);
    AV_WL32(file_data + 4, SOX_FIXED_HDR);
    AV_WL64(file_data + 16, UINT64_C(0x7ff8000000000000));
    AV_WL32(file_data + 24, 1);

    format = avformat_alloc_context();
    avio_buffer = av_malloc(4096);
    if (!format || !avio_buffer)
        return 2;
    avio = avio_alloc_context(avio_buffer, 4096, 0, &input,
                              read_packet, NULL, NULL);
    if (!avio)
        return 2;
    format->pb = avio;

    fprintf(stderr, "sample_rate_bits=0x%016llx decoded_is_nan=%d\n",
            (unsigned long long)AV_RL64(file_data + 16),
            isnan(av_int2double(AV_RL64(file_data + 16))));
    fflush(stderr);
    result = sox_read_header(format);
    fprintf(stderr, "read_header_result=%d\n", result);

    format->pb = NULL;
    avio_context_free(&avio);
    avformat_free_context(format);
    return result == AVERROR_INVALIDDATA ? 0 : result;
}
