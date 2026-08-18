#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "libavutil/imgutils.h"
#include "libavutil/mem.h"

#if defined(PIXELIZE_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

#ifndef PIXELIZE_SOURCE
#define PIXELIZE_SOURCE "libavfilter/vf_pixelize.c"
#endif
#include PIXELIZE_SOURCE

static uint8_t *frame_start;
static int first_block = 1;

static int consume_block(const uint8_t *src, uint8_t *dst,
                         ptrdiff_t src_linesize, ptrdiff_t dst_linesize,
                         int width, int height)
{
    volatile uint8_t value;

    if (first_block) {
        fprintf(stderr,
                "first_block_row=%td width=%d height=%d\n",
                (src - frame_start) / src_linesize, width, height);
        fflush(stderr);
        first_block = 0;
    }
    value = *src;
    *dst = value;
    (void)dst_linesize;
    return 0;
}

int main(void)
{
    const int width = 1;
    const int height = 2080410;
    const int jobnr = 2064;
    const int nb_jobs = 2065;
    const size_t guard_rows = 485;
    const int linesize = 1;
    const size_t data_size = guard_rows + (size_t)height;
    const int wrapped_start =
        (int32_t)((uint32_t)height * (uint32_t)jobnr) / nb_jobs;
    const int wrapped_end =
        (int32_t)((uint32_t)height * (uint32_t)(jobnr + 1)) / nb_jobs;
    const int exact_start = (int)((int64_t)height * jobnr / nb_jobs);
    const int exact_end = (int)((int64_t)height * (jobnr + 1) / nb_jobs);
    PixelizeContext pixelize = { 0 };
    AVFilterContext filter_context = { .priv = &pixelize };
    AVFrame in = { 0 };
    AVFrame out = { 0 };
    ThreadData td = { .in = &in, .out = &out };
    uint8_t *in_base = av_mallocz(data_size);
    uint8_t *out_base = av_mallocz(data_size);
    int result;

    if (!in_base || !out_base) {
        av_free(in_base);
        av_free(out_base);
        return 2;
    }

    pixelize.mode = PIXELIZE_AVG;
    pixelize.planes = 1;
    pixelize.depth = 8;
    pixelize.nb_planes = 1;
    pixelize.linesize[0] = linesize;
    pixelize.planewidth[0] = width;
    pixelize.planeheight[0] = height;
    pixelize.block_w[0] = 1;
    pixelize.block_h[0] = 1;
    pixelize.pixelize[PIXELIZE_AVG] = consume_block;

    in.width = out.width = width;
    in.height = out.height = height;
    in.linesize[0] = out.linesize[0] = linesize;
    in.data[0] = in_base + guard_rows;
    out.data[0] = out_base + guard_rows;
    frame_start = in.data[0];

#if defined(PIXELIZE_GUARDED_REPLAY)
    __asan_poison_memory_region(in_base, guard_rows);
    __asan_poison_memory_region(out_base, guard_rows);
#endif

    fprintf(stderr,
            "width=%d height=%d explicit_threads=%d jobnr=%d "
            "start_product=%lld end_product=%lld wrapped_start=%d "
            "wrapped_end=%d exact_start=%d exact_end=%d image_check=%d\n",
            width, height, nb_jobs, jobnr,
            (long long)height * jobnr,
            (long long)height * (jobnr + 1),
            wrapped_start, wrapped_end, exact_start, exact_end,
            av_image_check_size(width, height, 0, NULL));
    fflush(stderr);
    result = pixelize_slice(&filter_context, &td, jobnr, nb_jobs);
    fprintf(stderr, "filter_result=%d\n", result);

#if defined(PIXELIZE_GUARDED_REPLAY)
    __asan_unpoison_memory_region(in_base, guard_rows);
    __asan_unpoison_memory_region(out_base, guard_rows);
#endif
    av_free(in_base);
    av_free(out_base);
    return result;
}
