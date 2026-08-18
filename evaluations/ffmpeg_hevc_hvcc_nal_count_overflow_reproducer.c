#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef HEVC_SOURCE
#define HEVC_SOURCE "libavformat/hevc.c"
#endif
#include HEVC_SOURCE

static void put_nal(uint8_t **cursor)
{
    AV_WB16(*cursor, 2);
    *cursor += 2;
    *(*cursor)++ = HEVC_NAL_SEI_PREFIX << 1;
    *(*cursor)++ = 1; /* nuh_temporal_id_plus1 */
}

int main(void)
{
    const unsigned first_count = UINT16_MAX;
    const unsigned second_count = 1;
    const size_t input_size = 23 + 3 + first_count * 4 + 3 + second_count * 4;
    AVIOContext *output = NULL;
    uint8_t *output_data = NULL;
    uint8_t *input = av_mallocz(input_size);
    uint8_t *cursor;
    int output_size = 0;
    int ret;

    if (!input)
        return 2;

    input[0] = 1;  /* configurationVersion */
    input[21] = 3; /* lengthSizeMinusOne */
    input[22] = 2; /* two arrays with the same NAL type */
    cursor = input + 23;

    *cursor++ = HEVC_NAL_SEI_PREFIX;
    AV_WB16(cursor, first_count);
    cursor += 2;
    for (unsigned i = 0; i < first_count; i++)
        put_nal(&cursor);

    *cursor++ = HEVC_NAL_SEI_PREFIX;
    AV_WB16(cursor, second_count);
    cursor += 2;
    put_nal(&cursor);

    if (cursor != input + input_size)
        return 3;
    if (avio_open_dyn_buf(&output) < 0)
        return 4;

    fprintf(stderr,
            "hvcc_arrays=2 repeated_type=%d declared_nalus=%u input_bytes=%zu\n",
            HEVC_NAL_SEI_PREFIX, first_count + second_count, input_size);
    fflush(stderr);

    ret = ff_isom_write_hvcc(output, input, input_size, 0, NULL);
    if (ret < 0)
        ffio_free_dyn_buf(&output);
    else
        output_size = avio_close_dyn_buf(output, &output_data);

    fprintf(stderr, "write_result=%d rejected_invalid=%d output_bytes=%d\n",
            ret, ret == AVERROR_INVALIDDATA, output_size);
    av_free(output_data);
    av_free(input);

    return ret == AVERROR_INVALIDDATA ? 0 : 5;
}
