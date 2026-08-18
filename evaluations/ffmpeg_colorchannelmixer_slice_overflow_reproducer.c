#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef FILTERS_HEADER
#define FILTERS_HEADER "libavfilter/filters.h"
#endif
#include FILTERS_HEADER

#ifndef COLORCHANNELMIXER_SOURCE
#define COLORCHANNELMIXER_SOURCE "libavfilter/vf_colorchannelmixer.c"
#endif
#include COLORCHANNELMIXER_SOURCE

int main(void)
{
    const int height = 2080410;
    const int jobnr = 2064;
    const int nb_jobs = 2065;
    ColorChannelMixerContext private_context = { 0 };
    AVFilterContext filter_context = { 0 };
    AVFrame frame = { 0 };
    ThreadData thread_data = { .in = &frame, .out = &frame };
    uint8_t *pixels = calloc((size_t)height, 3);
    int *luts = calloc(4 * 4 * 256, sizeof(*luts));

    if (!pixels || !luts)
        return 2;
    memset(pixels, 127, (size_t)height * 3);

    for (int output = 0; output < 4; output++) {
        for (int input = 0; input < 4; input++) {
            int *lut = luts + (output * 4 + input) * 256;

            private_context.lut[output][input] = lut;
            if (output == input) {
                for (int value = 0; value < 256; value++)
                    lut[value] = value;
            }
        }
    }
    private_context.rgba_map[R] = 0;
    private_context.rgba_map[G] = 1;
    private_context.rgba_map[B] = 2;
    private_context.rgba_map[A] = 0;
    filter_context.priv = &private_context;
    frame.width = 1;
    frame.height = height;
    frame.data[0] = pixels;
    frame.linesize[0] = 3;

    fprintf(stderr,
            "height=%d width=1 jobnr=%d nb_jobs=%d start_product=%lld "
            "end_product=%lld\n",
            height, jobnr, nb_jobs, (long long)height * jobnr,
            (long long)height * (jobnr + 1));
    fflush(stderr);

    filter_slice_rgba_packed_8(&filter_context, &thread_data,
                               jobnr, nb_jobs, 0, 3, 0, 8);
    fprintf(stderr, "last_pixel=%u\n", pixels[(size_t)(height - 1) * 3]);

    free(luts);
    free(pixels);
    return 0;
}
