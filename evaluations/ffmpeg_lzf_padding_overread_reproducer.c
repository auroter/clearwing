#include <stdint.h>
#include <stdio.h>

#include "libavcodec/bytestream.h"
#include "libavcodec/get_bits.h"
#include "libavcodec/lzf.h"
#include "libavutil/mem.h"

int main(void)
{
    uint8_t compressed[69 + AV_INPUT_BUFFER_PADDING_SIZE] = { 0 };
    uint8_t *output = NULL;
    size_t output_size = 0;
    unsigned allocated_size = 0;
    GetByteContext bytes;
    GetBitContext bits;
    size_t p = 0;

    /* Two 32-byte literal runs make av_fast_realloc reserve 66 bytes;
     * the final two-byte run fills that allocation exactly. */
    compressed[p++] = 31;
    for (int i = 0; i < 32; i++)
        compressed[p++] = (uint8_t)i;
    compressed[p++] = 31;
    for (int i = 0; i < 32; i++)
        compressed[p++] = (uint8_t)(32 + i);
    compressed[p++] = 1;
    compressed[p++] = 64;
    compressed[p++] = 65;

    bytestream2_init(&bytes, compressed, p);
    if (ff_lzf_uncompress(&bytes, &output, &output_size, &allocated_size) < 0)
        return 2;
    fprintf(stderr, "compressed=%zu output=%zu allocated=%u\n",
            p, output_size, allocated_size);
    fflush(stderr);
    if (output_size != 66)
        return 3;

    /* NotchLC likewise initializes a GetBitContext over the LZF output.
     * The bit-reader contract requires AV_INPUT_BUFFER_PADDING_SIZE bytes. */
    if (init_get_bits8(&bits, output, output_size) < 0)
        return 4;
    skip_bits_long(&bits, 64 * 8);
    fprintf(stderr, "tail=%u\n", get_bits(&bits, 16));

    av_free(output);
    return 0;
}
