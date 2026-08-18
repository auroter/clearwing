#include <stdint.h>
#include <stdio.h>

#include "libavutil/mem.h"

#if defined(ASOFTCLIP_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

#ifndef ASOFTCLIP_SOURCE
#define ASOFTCLIP_SOURCE "libavfilter/af_asoftclip.c"
#endif
#include ASOFTCLIP_SOURCE

static void consume_channels(ASoftClipContext *s, void **dst,
                             const void **src, int nb_samples,
                             int channels, int start, int end)
{
    volatile const void *value;

    fprintf(stderr, "slice_start=%d slice_end=%d\n", start, end);
    fflush(stderr);
    value = src[start];
    dst[start] = (void *)value;
    (void)s;
    (void)nb_samples;
    (void)channels;
}

int main(void)
{
    const int channels = 65536;
    const int jobnr = 32768;
    const int nb_jobs = 65536;
    ASoftClipContext softclip = { .filter = consume_channels };
    AVFilterContext filter_context = { .priv = &softclip };
    AVFrame in = { 0 };
    AVFrame out = { 0 };
    ThreadData thread_data = {
        .in = &in,
        .out = &out,
        .nb_samples = 1,
        .channels = channels,
    };
    uint8_t sample = 0;
    uint8_t **in_data;
    uint8_t **out_data;
#if defined(ASOFTCLIP_GUARDED_REPLAY)
    const size_t guard_channels = 32769;
    uint8_t **in_base = av_calloc(
        guard_channels + channels, sizeof(*in_base));
    uint8_t **out_base = av_calloc(
        guard_channels + channels, sizeof(*out_base));

    if (!in_base || !out_base)
        return 2;
    in_data = in_base + guard_channels;
    out_data = out_base + guard_channels;
    __asan_poison_memory_region(
        in_base, guard_channels * sizeof(*in_base));
    __asan_poison_memory_region(
        out_base, guard_channels * sizeof(*out_base));
#else
    in_data = av_calloc(channels, sizeof(*in_data));
    out_data = av_calloc(channels, sizeof(*out_data));
    if (!in_data || !out_data)
        return 2;
#endif

    for (int i = 0; i < channels; i++) {
        in_data[i] = &sample;
        out_data[i] = &sample;
    }
    in.extended_data = in_data;
    out.extended_data = out_data;

    fprintf(stderr,
            "channels=%d explicit_threads=%d jobnr=%d "
            "start_product=%lld end_product=%lld\n",
            channels, nb_jobs, jobnr,
            (long long)channels * jobnr,
            (long long)channels * (jobnr + 1));
    fflush(stderr);
    filter_channels(&filter_context, &thread_data, jobnr, nb_jobs);
    fprintf(stderr, "filter_result=0\n");

#if defined(ASOFTCLIP_GUARDED_REPLAY)
    __asan_unpoison_memory_region(
        in_base, guard_channels * sizeof(*in_base));
    __asan_unpoison_memory_region(
        out_base, guard_channels * sizeof(*out_base));
    av_free(in_base);
    av_free(out_base);
#else
    av_free(in_data);
    av_free(out_data);
#endif
    return 0;
}
