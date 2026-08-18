#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef FLOODFILL_SOURCE
#define FLOODFILL_SOURCE "libavfilter/vf_floodfill.c"
#endif
#include FLOODFILL_SOURCE

int ff_inlink_make_frame_writable(AVFilterLink *link, AVFrame **rframe)
{
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
    const int frame_width = 8;
    const int frame_height = 8;
    FloodfillContext private_context = { 0 };
    AVFilterContext filter_context = { 0 };
    AVFilterLink input_link = { 0 };
    AVFilterLink output_link = { 0 };
    AVFilterLink *output_link_pointer = &output_link;
    AVFrame frame = { 0 };
    uint8_t *pixels = calloc((size_t)frame_width * frame_height, 1);
    int ret;

    if (!pixels)
        return 2;

    private_context.s[0] = 0;
    private_context.d[0] = 1;
    filter_context.priv = &private_context;
    filter_context.outputs = &output_link_pointer;
    input_link.dst = &filter_context;
    input_link.format = AV_PIX_FMT_GRAY8;
    input_link.w = configured_width;
    input_link.h = configured_height;
    frame.width = frame_width;
    frame.height = frame_height;
    frame.format = AV_PIX_FMT_GRAY8;
    frame.data[0] = pixels;
    frame.linesize[0] = frame_width;

    ret = config_input(&input_link);
    if (ret < 0)
        return 3;

    fprintf(stderr,
            "configured=%dx%d configured_point_slots=%d frame=%dx%d "
            "required_point_slots=%d\n",
            configured_width, configured_height,
            configured_width * configured_height * 4,
            frame_width, frame_height, frame_width * frame_height * 4);
    fflush(stderr);

    ret = filter_frame(&input_link, &frame);
    fprintf(stderr, "filter_result=%d final_pixel=%u\n", ret,
            pixels[(size_t)frame_width * frame_height - 1]);

    uninit(&filter_context);
    free(pixels);
    return ret < 0;
}
