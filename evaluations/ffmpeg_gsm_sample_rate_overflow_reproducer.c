#include <limits.h>
#include <stdio.h>

#ifndef GSMDEC_SOURCE
#define GSMDEC_SOURCE "libavformat/gsmdec.c"
#endif
#include GSMDEC_SOURCE

int main(void)
{
    const int sample_rate = INT_MAX / GSM_BLOCK_SIZE;
    const long long mathematical_numerator =
        (long long)GSM_BLOCK_SIZE * 8 * sample_rate;
    GSMDemuxerContext demuxer = { .sample_rate = sample_rate };
    AVFormatContext *format = avformat_alloc_context();
    int result;

    if (!format)
        return 2;
    format->priv_data = &demuxer;
    fprintf(stderr,
            "sample_rate=%d option_max=%d block_size=%d "
            "mathematical_numerator=%lld mathematical_bit_rate=%lld\n",
            sample_rate, INT_MAX / GSM_BLOCK_SIZE, GSM_BLOCK_SIZE,
            mathematical_numerator,
            mathematical_numerator / GSM_BLOCK_SAMPLES);
    fflush(stderr);
    result = gsm_read_header(format);
    fprintf(stderr, "header_result=%d bit_rate=%lld\n", result,
            format->nb_streams ? (long long)format->streams[0]->codecpar->bit_rate
                               : -1LL);

    format->priv_data = NULL;
    avformat_free_context(format);
    return result < 0;
}
