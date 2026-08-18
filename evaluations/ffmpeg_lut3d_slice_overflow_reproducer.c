#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "libavfilter/lut3d.h"
#include "libavutil/imgutils.h"
#include "libavutil/mem.h"

#if defined(LUT3D_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

/* Emit the production x86 callback wrappers on this arm64 proof host. */
#undef ARCH_X86_64
#undef HAVE_AVX2_EXTERNAL
#undef HAVE_AVX_EXTERNAL
#undef HAVE_SSE2_EXTERNAL
#define ARCH_X86_64 1
#define HAVE_AVX2_EXTERNAL 0
#define HAVE_AVX_EXTERNAL 0
#define HAVE_SSE2_EXTERNAL 1

#ifndef LUT3D_SOURCE
#define LUT3D_SOURCE "libavfilter/x86/vf_lut3d_init.c"
#endif
#include LUT3D_SOURCE

static void consume_slice(AVFrame *src, int slice_start, int slice_end)
{
    volatile uint16_t value;

    fprintf(stderr, "simd_slice_start=%d simd_slice_end=%d\n",
            slice_start, slice_end);
    fflush(stderr);
    value = *(uint16_t *)(src->data[0] +
                         (ptrdiff_t)slice_start * src->linesize[0]);
    (void)value;
}

void ff_interp_tetrahedral_pf32_sse2(LUT3DContext *lut3d,
                                     Lut3DPreLut *prelut,
                                     AVFrame *src, AVFrame *dst,
                                     int slice_start, int slice_end,
                                     int has_alpha)
{
    (void)lut3d;
    (void)prelut;
    (void)dst;
    (void)has_alpha;
    consume_slice(src, slice_start, slice_end);
}

void ff_interp_tetrahedral_p16_sse2(LUT3DContext *lut3d,
                                    Lut3DPreLut *prelut,
                                    AVFrame *src, AVFrame *dst,
                                    int slice_start, int slice_end,
                                    int has_alpha)
{
    (void)lut3d;
    (void)prelut;
    (void)dst;
    (void)has_alpha;
    consume_slice(src, slice_start, slice_end);
}

int main(void)
{
    const int width = 1;
    const int height = 2080410;
    const int jobnr = 2064;
    const int nb_jobs = 2065;
    const size_t guard_rows = 485;
    const int linesize = 2;
    const size_t data_size = (guard_rows + (size_t)height) * linesize;
    LUT3DContext lut3d = { 0 };
    AVFilterContext filter_context = { .priv = &lut3d };
    AVFrame in = { 0 };
    AVFrame out = { 0 };
    ThreadData td = { .in = &in, .out = &out };
    uint8_t *base = av_mallocz(data_size);
    int result;

    if (!base)
        return 2;
    in.width = out.width = width;
    in.height = out.height = height;
    in.linesize[0] = out.linesize[0] = linesize;
    in.data[0] = out.data[0] = base + guard_rows * linesize;

#if defined(LUT3D_GUARDED_REPLAY)
    __asan_poison_memory_region(base, guard_rows * linesize);
#endif

    fprintf(stderr,
            "width=%d height=%d explicit_threads=%d jobnr=%d "
            "start_product=%lld end_product=%lld image_check=%d\n",
            width, height, nb_jobs, jobnr,
            (long long)height * jobnr,
            (long long)height * (jobnr + 1),
            av_image_check_size(width, height, 0, NULL));
    fflush(stderr);
    result = interp_tetrahedral_p16_sse2(&filter_context, &td,
                                         jobnr, nb_jobs);
    fprintf(stderr, "filter_result=%d\n", result);

#if defined(LUT3D_GUARDED_REPLAY)
    __asan_unpoison_memory_region(base, guard_rows * linesize);
#endif
    av_free(base);
    return result;
}
