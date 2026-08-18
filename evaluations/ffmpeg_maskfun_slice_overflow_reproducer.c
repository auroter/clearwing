#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FILTERS_HEADER
#define FILTERS_HEADER "libavfilter/filters.h"
#endif
#include FILTERS_HEADER

#ifndef MASKFUN_SOURCE
#define MASKFUN_SOURCE "libavfilter/vf_maskfun.c"
#endif
#include MASKFUN_SOURCE

int main(void)
{
    const int height = 2080410;
    const int jobnr = 2064;
    const int nb_jobs = 2065;
    MaskFunContext private_context = { 0 };
    AVFilterContext filter_context = { 0 };
    AVFrame input = { 0 };
    AVFrame output = { 0 };
    uint8_t *input_data = calloc(height, 1);
    uint8_t *output_data = calloc(height, 1);

    if (!input_data || !output_data)
        return 2;
    memset(input_data, 127, height);

    private_context.planes = 1;
    private_context.nb_planes = 1;
    private_context.planewidth[0] = 1;
    private_context.planeheight[0] = height;
    private_context.high = 255;
    private_context.max = 255;
    private_context.in = &input;
    filter_context.priv = &private_context;
    input.data[0] = input_data;
    input.linesize[0] = 1;
    output.data[0] = output_data;
    output.linesize[0] = 1;

    fprintf(stderr,
            "height=%d jobnr=%d nb_jobs=%d start_product=%lld "
            "end_product=%lld\n",
            height, jobnr, nb_jobs, (long long)height * jobnr,
            (long long)height * (jobnr + 1));
    fflush(stderr);

    maskfun8(&filter_context, &output, jobnr, nb_jobs);
    fprintf(stderr, "last_output=%u\n", output_data[height - 1]);

    free(output_data);
    free(input_data);
    return 0;
}
