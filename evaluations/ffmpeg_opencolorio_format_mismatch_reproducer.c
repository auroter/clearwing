#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/opt.h"
#include "libavutil/pixdesc.h"
#include "libavutil/pixfmt.h"

/*
 * Build the pinned filter even when libOpenColorIO is unavailable locally.
 * The format negotiation, output allocation, and downstream crash under test
 * are entirely on the FFmpeg side; the stubs below model a successful external
 * processor call without changing any frame geometry.
 */
#include "libavfilter/vf_opencolorio.c"

extern const FFFilter ff_vf_geq;

OCIOHandle ocio_create_output_colorspace_processor(AVFilterContext *ctx,
                                                    const char *config_path,
                                                    const char *input_color_space,
                                                    const char *output_color_space,
                                                    AVDictionary *params)
{
    return (OCIOHandle)(uintptr_t)1;
}

OCIOHandle ocio_create_display_view_processor(AVFilterContext *ctx,
                                              const char *config_path,
                                              const char *input_color_space,
                                              const char *display,
                                              const char *view, int inverse,
                                              AVDictionary *params)
{
    return (OCIOHandle)(uintptr_t)1;
}

OCIOHandle ocio_create_file_transform_processor(AVFilterContext *ctx,
                                                const char *file_transform,
                                                int inverse)
{
    return (OCIOHandle)(uintptr_t)1;
}

int ocio_finalize_processor(AVFilterContext *ctx, OCIOHandle handle,
                            int input_format, int output_format)
{
    return 0;
}

int ocio_apply(AVFilterContext *ctx, OCIOHandle handle, AVFrame *input_frame,
               AVFrame *output_frame, int y_start, int height)
{
    if (input_frame != output_frame) {
        for (int y = y_start; y < y_start + height; y++)
            for (int x = 0; x < output_frame->width * 3; x++)
                output_frame->data[0][y * output_frame->linesize[0] + x] =
                    (uint8_t)(x + y);
    }
    return 0;
}

void ocio_destroy_processor(AVFilterContext *ctx, OCIOHandle handle)
{
}

static void fail(int err, const char *what)
{
    char text[AV_ERROR_MAX_STRING_SIZE];

    av_strerror(err, text, sizeof(text));
    fprintf(stderr, "%s: %s\n", what, text);
    exit(1);
}

int main(void)
{
    const AVFilter *buffer = avfilter_get_by_name("buffer");
    const AVFilter *geq = &ff_vf_geq.p;
    const AVFilter *sink = avfilter_get_by_name("buffersink");
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *src = NULL, *ocio = NULL, *sum = NULL, *dst = NULL;
    AVFrame *in = NULL, *out = NULL;
    int ret;

    if (!buffer || !geq || !sink || !graph)
        fail(AVERROR(ENOMEM), "setup");

    ret = avfilter_graph_create_filter(
        &src, buffer, "src",
        "video_size=256x2:pix_fmt=gbrpf32le:time_base=1/1:pixel_aspect=1/1",
        NULL, graph);
    if (ret < 0)
        fail(ret, "create buffer");

    ocio = avfilter_graph_alloc_filter(graph, &ff_vf_ocio.p, "ocio");
    if (!ocio)
        fail(AVERROR(ENOMEM), "allocate ocio");
    ret = av_opt_set(ocio, "filetransform", "stub", AV_OPT_SEARCH_CHILDREN);
    if (ret < 0)
        fail(ret, "set filetransform");
    ret = av_opt_set(ocio, "format", "rgb24", AV_OPT_SEARCH_CHILDREN);
    if (ret < 0)
        fail(ret, "set format");
    ret = avfilter_init_str(ocio, NULL);
    if (ret < 0)
        fail(ret, "init ocio");

    ret = avfilter_graph_create_filter(
        &sum, geq, "geq", "g=gsum(X,Y):b=bsum(X,Y):r=rsum(X,Y)", NULL,
        graph);
    if (ret < 0)
        fail(ret, "create geq");
    ret = avfilter_graph_create_filter(&dst, sink, "sink", NULL, NULL, graph);
    if (ret < 0)
        fail(ret, "create sink");

    if ((ret = avfilter_link(src, 0, ocio, 0)) < 0 ||
        (ret = avfilter_link(ocio, 0, sum, 0)) < 0 ||
        (ret = avfilter_link(sum, 0, dst, 0)) < 0 ||
        (ret = avfilter_graph_config(graph, NULL)) < 0)
        fail(ret, "configure graph");

    printf("negotiated=%s selected=%s\n",
           av_get_pix_fmt_name(ocio->outputs[0]->format),
           av_get_pix_fmt_name(((OCIOContext *)ocio->priv)->output_format));
    fflush(stdout);

    in = av_frame_alloc();
    out = av_frame_alloc();
    if (!in || !out)
        fail(AVERROR(ENOMEM), "allocate frames");
    in->format = AV_PIX_FMT_GBRPF32LE;
    in->width = 256;
    in->height = 2;
    if ((ret = av_frame_get_buffer(in, 32)) < 0)
        fail(ret, "allocate input");

    ret = av_buffersrc_add_frame_flags(src, in, AV_BUFFERSRC_FLAG_KEEP_REF);
    if (ret < 0)
        fail(ret, "push input");
    ret = av_buffersink_get_frame(dst, out);
    if (ret < 0)
        fail(ret, "pull output");

    printf("unexpected-success format=%s\n", av_get_pix_fmt_name(out->format));
    av_frame_free(&in);
    av_frame_free(&out);
    avfilter_graph_free(&graph);
    return 2;
}
