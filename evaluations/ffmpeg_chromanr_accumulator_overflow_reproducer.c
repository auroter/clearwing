#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/buffer.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

#define FRAME_SIZE 201

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

static AVFrame *make_frame(void)
{
    const int linesize = FRAME_SIZE * (int)sizeof(uint16_t);
    const int plane_size = linesize * FRAME_SIZE;
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    for (int plane = 0; plane < 3; plane++) {
        frame->buf[plane] = av_buffer_alloc(plane_size);
        if (!frame->buf[plane]) {
            av_frame_free(&frame);
            return NULL;
        }
        frame->data[plane] = frame->buf[plane]->data;
        frame->linesize[plane] = linesize;
        for (int sample = 0; sample < FRAME_SIZE * FRAME_SIZE; sample++)
            ((uint16_t *)frame->data[plane])[sample] = UINT16_MAX;
    }
    frame->format = AV_PIX_FMT_YUV444P16LE;
    frame->width = FRAME_SIZE;
    frame->height = FRAME_SIZE;
    frame->pts = 0;
    return frame;
}

int main(void)
{
    const char *source_args =
        "video_size=201x201:pix_fmt=yuv444p16le:time_base=1/1:pixel_aspect=1/1";
    const char *chromanr_args =
        "sizew=100:sizeh=100:stepw=1:steph=1:thres=200";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *chromanr = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&chromanr, graph, "chromanr", "chromanr",
                      chromanr_args) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, chromanr, 0) < 0 ||
        avfilter_link(chromanr, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    input = make_frame();
    output = av_frame_alloc();
    if (!input || !output) {
        fprintf(stderr, "frame_allocation_failed=1\n");
        goto done;
    }
    fprintf(stderr,
            "frame=201x201 format=yuv444p16le neighborhood=201x201 "
            "samples_with_initial=40402 sample_value=65535 "
            "mathematical_accumulator=2647745070 int_max=2147483647\n");
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
