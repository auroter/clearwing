#include <stdint.h>
#include <stdio.h>

#include "libavutil/mem.h"

#if defined(AEMPHASIS_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

#ifndef AEMPHASIS_SOURCE
#define AEMPHASIS_SOURCE "libavfilter/af_aemphasis.c"
#endif
#include AEMPHASIS_SOURCE

int main(void)
{
    const int channels = 65536;
    const int jobnr = 32768;
    const int nb_jobs = 65536;
    AudioEmphasisContext emphasis = {
        .level_in = 1.0,
        .level_out = 1.0,
    };
    AVFilterContext filter_context = { .priv = &emphasis };
    AVFrame in = { 0 };
    AVFrame out = { 0 };
    AVFrame work = { 0 };
    ThreadData thread_data = { .in = &in, .out = &out };
    double sample[4] = { 0 };
    uint8_t **in_data;
    uint8_t **out_data;
    uint8_t **work_data;
#if defined(AEMPHASIS_GUARDED_REPLAY)
    const size_t guard_channels = 32769;
    uint8_t **in_base = av_calloc(guard_channels + channels, sizeof(*in_base));
    uint8_t **out_base = av_calloc(guard_channels + channels, sizeof(*out_base));
    uint8_t **work_base = av_calloc(guard_channels + channels, sizeof(*work_base));

    if (!in_base || !out_base || !work_base)
        return 2;
    in_data = in_base + guard_channels;
    out_data = out_base + guard_channels;
    work_data = work_base + guard_channels;
    __asan_poison_memory_region(in_base, guard_channels * sizeof(*in_base));
    __asan_poison_memory_region(out_base, guard_channels * sizeof(*out_base));
    __asan_poison_memory_region(work_base, guard_channels * sizeof(*work_base));
#else
    in_data = av_calloc(channels, sizeof(*in_data));
    out_data = av_calloc(channels, sizeof(*out_data));
    work_data = av_calloc(channels, sizeof(*work_data));
    if (!in_data || !out_data || !work_data)
        return 2;
#endif

    for (int i = 0; i < channels; i++) {
        in_data[i] = (uint8_t *)sample;
        out_data[i] = (uint8_t *)sample;
        work_data[i] = (uint8_t *)sample;
    }
    in.extended_data = in_data;
    in.ch_layout.order = AV_CHANNEL_ORDER_UNSPEC;
    in.ch_layout.nb_channels = channels;
    in.nb_samples = 1;
    out.extended_data = out_data;
    work.extended_data = work_data;
    emphasis.w = &work;

    fprintf(stderr,
            "channels=%d explicit_threads=%d jobnr=%d "
            "start_product=%lld end_product=%lld\n",
            channels, nb_jobs, jobnr,
            (long long)channels * jobnr,
            (long long)channels * (jobnr + 1));
    fflush(stderr);
    filter_channels(&filter_context, &thread_data, jobnr, nb_jobs);
    fprintf(stderr, "filter_result=0 sample=%g\n", sample[0]);

#if defined(AEMPHASIS_GUARDED_REPLAY)
    __asan_unpoison_memory_region(in_base, guard_channels * sizeof(*in_base));
    __asan_unpoison_memory_region(out_base, guard_channels * sizeof(*out_base));
    __asan_unpoison_memory_region(work_base, guard_channels * sizeof(*work_base));
    av_free(in_base);
    av_free(out_base);
    av_free(work_base);
#else
    av_free(in_data);
    av_free(out_data);
    av_free(work_data);
#endif
    return 0;
}
