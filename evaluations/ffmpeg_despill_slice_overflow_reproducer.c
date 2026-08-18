#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FILTERS_HEADER
#define FILTERS_HEADER "libavfilter/filters.h"
#endif
#include FILTERS_HEADER

#ifndef DESPILL_SOURCE
#define DESPILL_SOURCE "libavfilter/vf_despill.c"
#endif
#include DESPILL_SOURCE

int main(void)
{
    const int height = 2080410;
    const int jobnr = 2064;
    const int nb_jobs = 2065;
    DespillContext private_context = { 0 };
    AVFilterContext filter_context = { 0 };
    AVFrame frame = { 0 };
    uint8_t *pixels = calloc((size_t)height, 4);

    if (!pixels)
        return 2;
    memset(pixels, 127, (size_t)height * 4);

    private_context.co[0] = 0;
    private_context.co[1] = 1;
    private_context.co[2] = 2;
    private_context.co[3] = 3;
    private_context.spillmix = 0.5f;
    filter_context.priv = &private_context;
    frame.width = 1;
    frame.height = height;
    frame.data[0] = pixels;
    frame.linesize[0] = 4;

    fprintf(stderr,
            "height=%d width=1 jobnr=%d nb_jobs=%d start_product=%lld "
            "end_product=%lld\n",
            height, jobnr, nb_jobs, (long long)height * jobnr,
            (long long)height * (jobnr + 1));
    fflush(stderr);

    do_despill_slice(&filter_context, &frame, jobnr, nb_jobs);
    fprintf(stderr, "last_pixel=%u\n", pixels[(size_t)(height - 1) * 4]);

    free(pixels);
    return 0;
}
