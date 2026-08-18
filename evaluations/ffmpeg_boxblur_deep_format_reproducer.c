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

static int create_filter(AVFilterContext **context, AVFilterGraph *graph,
                         const char *filter_name, const char *instance_name,
                         const char *arguments)
{
    const AVFilter *filter = avfilter_get_by_name(filter_name);

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
    frame->buf[0] = av_buffer_alloc(64);
    if (!frame->buf[0]) {
        av_frame_free(&frame);
        return NULL;
    }
    frame->data[0] = frame->buf[0]->data;
    frame->linesize[0] = 16;
    memset(frame->data[0], 0x3F, 64);
    frame->format = AV_PIX_FMT_GRAYF32LE;
    frame->width = 4;
    frame->height = 4;
    frame->pts = 0;
    return frame;
}

int main(void)
{
    const char *source_args =
        "video_size=4x4:pix_fmt=grayf32le:time_base=1/1:pixel_aspect=1/1";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *boxblur = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&boxblur, graph, "boxblur", "boxblur", NULL) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, boxblur, 0) < 0 ||
        avfilter_link(boxblur, 0, sink, 0) < 0 ||
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
            "frame=4x4 format=grayf32le depth=32 pixel_size=4 "
            "temp_bytes_per_dimension=8 blur=boxblur\n");
    fflush(stderr);
    if (av_buffersrc_add_frame_flags(source, input, 0) < 0 ||
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
