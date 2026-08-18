#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef ALPHAMERGE_SOURCE
#define ALPHAMERGE_SOURCE "libavfilter/vf_alphamerge.c"
#endif
#include ALPHAMERGE_SOURCE

static AVFrame *proof_main_frame;
static AVFrame *proof_alpha_frame;

int ff_framesync_dualinput_get_writable(FFFrameSync *fs, AVFrame **f0,
                                        AVFrame **f1)
{
    *f0 = proof_main_frame;
    *f1 = proof_alpha_frame;
    return 0;
}

int ff_filter_frame(AVFilterLink *link, AVFrame *frame)
{
    return 0;
}

int main(void)
{
    const int configured_width = 1;
    const int configured_height = 1;
    const int main_width = 8;
    const int main_height = 8;
    const int alpha_width = 1;
    const int alpha_height = 1;
    AlphaMergeContext private_context = { 0 };
    AVFilterContext filter_context = { 0 };
    AVFilterLink output_link = { 0 };
    AVFilterLink *output_link_pointer = &output_link;
    AVFrame main_frame = { 0 };
    AVFrame alpha_frame = { 0 };
    uint8_t *main_pixels = calloc((size_t)main_width * main_height, 4);
    uint8_t *alpha_pixels = malloc(1);
    int ret;

    if (!main_pixels || !alpha_pixels)
        return 2;
    alpha_pixels[0] = 0x7f;

    private_context.is_packed_rgb = 1;
    private_context.rgba_map[A] = 3;
    private_context.fs.parent = &filter_context;
    filter_context.priv = &private_context;
    filter_context.outputs = &output_link_pointer;
    output_link.alpha_mode = AVALPHA_MODE_STRAIGHT;

    main_frame.width = main_width;
    main_frame.height = main_height;
    main_frame.format = AV_PIX_FMT_RGBA;
    main_frame.data[0] = main_pixels;
    main_frame.linesize[0] = main_width * 4;
    alpha_frame.width = alpha_width;
    alpha_frame.height = alpha_height;
    alpha_frame.format = AV_PIX_FMT_GRAY8;
    alpha_frame.color_range = AVCOL_RANGE_JPEG;
    alpha_frame.data[0] = alpha_pixels;
    alpha_frame.linesize[0] = alpha_width;
    proof_main_frame = &main_frame;
    proof_alpha_frame = &alpha_frame;

    fprintf(stderr,
            "configured_main=%dx%d configured_alpha=%dx%d "
            "runtime_main=%dx%d runtime_alpha=%dx%d\n",
            configured_width, configured_height,
            configured_width, configured_height,
            main_width, main_height, alpha_width, alpha_height);
    fflush(stderr);

    ret = do_alphamerge(&private_context.fs);
    fprintf(stderr, "alphamerge_result=%d\n", ret);

    free(alpha_pixels);
    free(main_pixels);
    return ret < 0;
}
