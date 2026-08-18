#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#include "chromaprint.h"

struct ChromaprintContext {
    int unused;
};

static struct ChromaprintContext proof_context;
static uint32_t proof_fingerprint;

ChromaprintContext *chromaprint_new(int algorithm)
{
    return &proof_context;
}

void chromaprint_free(ChromaprintContext *ctx)
{
}

int chromaprint_set_option(ChromaprintContext *ctx, const char *name, int value)
{
    return 1;
}

int chromaprint_start(ChromaprintContext *ctx, int sample_rate, int channels)
{
    return 1;
}

int chromaprint_feed(ChromaprintContext *ctx, const int16_t *data, int size)
{
    return 1;
}

int chromaprint_finish(ChromaprintContext *ctx)
{
    return 1;
}

int chromaprint_get_raw_fingerprint(ChromaprintContext *ctx,
                                    uint32_t **fingerprint, int *size)
{
    *fingerprint = &proof_fingerprint;
    *size = INT_MAX / 4 + 1;
    return 1;
}

int chromaprint_encode_fingerprint(const uint32_t *fingerprint, int size,
                                   int algorithm, char **encoded,
                                   int *encoded_size, int base64)
{
    return 0;
}

void chromaprint_dealloc(void *pointer)
{
}

#ifndef CHROMAPRINT_SOURCE
#define CHROMAPRINT_SOURCE "libavformat/chromaprint.c"
#endif
#include CHROMAPRINT_SOURCE

int main(void)
{
    ChromaprintMuxContext mux_context = {
        .ctx = &proof_context,
        .fp_format = FINGERPRINT_RAW,
    };
    AVFormatContext format_context = {
        .priv_data = &mux_context,
    };
    const int entries = INT_MAX / 4 + 1;
    int ret;

    fprintf(stderr,
            "raw_fingerprint_entries=%d mathematical_bytes=%llu int_max=%d\n",
            entries, (unsigned long long)entries * 4, INT_MAX);
    fflush(stderr);

    ret = write_trailer(&format_context);
    fprintf(stderr, "write_trailer_result=%d rejected=%d\n", ret, ret < 0);
    return ret < 0 ? 0 : 5;
}
