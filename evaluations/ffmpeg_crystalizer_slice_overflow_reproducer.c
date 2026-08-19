#include <stdint.h>
#include <stdio.h>

#include "libavutil/mem.h"

#if defined(CRYSTALIZER_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

#ifndef CRYSTALIZER_SOURCE
#define CRYSTALIZER_SOURCE "libavfilter/af_crystalizer.c"
#endif
#include CRYSTALIZER_SOURCE

int main(void)
{
    const int channels = 65536;
    const int jobnr = 32768;
    const int nb_jobs = 65536;
    AVFilterContext filter_context = { 0 };
    ThreadData thread_data = {
        .nb_samples = 1,
        .channels = channels,
        .mult = 2.0f,
    };
    float sample = 0.25f;
    uint8_t **source_data;
    uint8_t **previous_data;
    uint8_t **destination_data;
#if defined(CRYSTALIZER_GUARDED_REPLAY)
    const size_t guard_channels = 32769;
    uint8_t **source_base = av_calloc(
        guard_channels + channels, sizeof(*source_base));
    uint8_t **previous_base = av_calloc(
        guard_channels + channels, sizeof(*previous_base));
    uint8_t **destination_base = av_calloc(
        guard_channels + channels, sizeof(*destination_base));

    if (!source_base || !previous_base || !destination_base)
        return 2;
    source_data = source_base + guard_channels;
    previous_data = previous_base + guard_channels;
    destination_data = destination_base + guard_channels;
    __asan_poison_memory_region(
        source_base, guard_channels * sizeof(*source_base));
    __asan_poison_memory_region(
        previous_base, guard_channels * sizeof(*previous_base));
    __asan_poison_memory_region(
        destination_base, guard_channels * sizeof(*destination_base));
#else
    source_data = av_calloc(channels, sizeof(*source_data));
    previous_data = av_calloc(channels, sizeof(*previous_data));
    destination_data = av_calloc(channels, sizeof(*destination_data));
    if (!source_data || !previous_data || !destination_data)
        return 2;
#endif

    for (int i = 0; i < channels; i++) {
        source_data[i] = (uint8_t *)&sample;
        previous_data[i] = (uint8_t *)&sample;
        destination_data[i] = (uint8_t *)&sample;
    }
    thread_data.s = (const void **)source_data;
    thread_data.p = (void **)previous_data;
    thread_data.d = (void **)destination_data;

    fprintf(stderr,
            "channels=%d explicit_threads=%d jobnr=%d "
            "start_product=%lld end_product=%lld\n",
            channels, nb_jobs, jobnr,
            (long long)channels * jobnr,
            (long long)channels * (jobnr + 1));
    fflush(stderr);
    filter_noinverse_fltp_clip(
        &filter_context, &thread_data, jobnr, nb_jobs);
    fprintf(stderr, "selected_channel_value=%f\n", sample);

#if defined(CRYSTALIZER_GUARDED_REPLAY)
    __asan_unpoison_memory_region(
        source_base, guard_channels * sizeof(*source_base));
    __asan_unpoison_memory_region(
        previous_base, guard_channels * sizeof(*previous_base));
    __asan_unpoison_memory_region(
        destination_base, guard_channels * sizeof(*destination_base));
    av_free(source_base);
    av_free(previous_base);
    av_free(destination_base);
#else
    av_free(source_data);
    av_free(previous_data);
    av_free(destination_data);
#endif
    return 0;
}
