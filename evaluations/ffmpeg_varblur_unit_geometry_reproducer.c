#include <stdint.h>
#include <stdio.h>

#include "libavfilter/vf_varblur.c"

int main(void)
{
    VarBlurContext state = { 0 };
    AVFilterContext filter = { 0 };
    uint32_t sat[4] = { 0 };
    uint8_t radius = 255;
    uint8_t destination = 0;

    state.min_radius = 0;
    state.max_radius = 8;
    state.depth = 8;
    filter.priv = &state;

    fprintf(stderr,
            "filter=varblur width=1 height=1 depth=8 x=0 y=0 "
            "horizontal_span=0 vertical_span=0 divisor=0\n");
    fflush(stderr);
    return blur_plane8(&filter, &destination, 1, &radius, 1,
                       1, 1, (const uint8_t *)sat, 8, 0, 1);
}
