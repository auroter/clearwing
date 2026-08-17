#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/buffer.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

#include "libavfilter/vf_deblock.c"

static int create_filter(AVFilterContext **context, AVFilterGraph *graph,
                         const char *filter_name, const char *instance_name,
                         const char *arguments)
{
    const AVFilter *filter = !strcmp(filter_name, "deblock")
                                 ? &ff_vf_deblock.p
                                 : avfilter_get_by_name(filter_name);

    if (!filter)
        return AVERROR_FILTER_NOT_FOUND;
    return avfilter_graph_create_filter(context, filter, instance_name,
                                        arguments, NULL, graph);
}

static AVFrame *make_tight_frame(void)
{
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->buf[0] = av_buffer_alloc(9 * 8);
    if (!frame->buf[0]) {
        av_frame_free(&frame);
        return NULL;
    }
    frame->format = AV_PIX_FMT_GRAY8;
    frame->width = 9;
    frame->height = 8;
    frame->data[0] = frame->buf[0]->data;
    frame->linesize[0] = 9;
    memset(frame->data[0], 0x40, 9 * 8);
    return frame;
}

int main(void)
{
    const char *source_args =
        "video_size=9x8:pix_fmt=gray:time_base=1/1:pixel_aspect=1/1";
    const char *deblock_args =
        "filter=strong:block=8:alpha=1:beta=1:gamma=1:delta=1";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *deblock = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&deblock, graph, "deblock", "deblock", deblock_args) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, deblock, 0) < 0 ||
        avfilter_link(deblock, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    input = make_tight_frame();
    output = av_frame_alloc();
    if (!input || !output) {
        fprintf(stderr, "frame_allocation_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "input_width=9 input_height=8 linesize=9 buffer_size=72 "
            "block=8 final_boundary_x=8 strong_right_radius=2\n");
    fflush(stderr);
    if (av_buffersrc_add_frame(source, input) < 0 ||
        av_buffersink_get_frame(sink, output) < 0) {
        fprintf(stderr, "frame_processing_failed=1\n");
        goto done;
    }
    fprintf(stderr, "unexpected_filter_success=1\n");
    ret = 0;

done:
    av_frame_free(&input);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret;
}
