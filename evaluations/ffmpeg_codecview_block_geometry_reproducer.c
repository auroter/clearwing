#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/buffer.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"
#include "libavutil/video_enc_params.h"

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
    AVVideoEncParams *params;
    AVVideoBlockParams *block;

    if (!frame)
        return NULL;
    frame->buf[0] = av_buffer_alloc(16);
    frame->buf[1] = av_buffer_alloc(4);
    frame->buf[2] = av_buffer_alloc(4);
    if (!frame->buf[0] || !frame->buf[1] || !frame->buf[2]) {
        av_frame_free(&frame);
        return NULL;
    }

    frame->format = AV_PIX_FMT_YUV420P;
    frame->width = 4;
    frame->height = 4;
    frame->pts = 0;
    frame->data[0] = frame->buf[0]->data;
    frame->data[1] = frame->buf[1]->data;
    frame->data[2] = frame->buf[2]->data;
    frame->linesize[0] = 4;
    frame->linesize[1] = 2;
    frame->linesize[2] = 2;

    params = av_video_enc_params_create_side_data(
        frame, AV_VIDEO_ENC_PARAMS_H264, 1);
    if (!params) {
        av_frame_free(&frame);
        return NULL;
    }
    block = av_video_enc_params_block(params, 0);
    block->src_x = 0;
    block->src_y = 4;
    block->w = 1;
    block->h = 1;
    return frame;
}

int main(void)
{
    const char *source_args =
        "video_size=4x4:pix_fmt=yuv420p:time_base=1/1:pixel_aspect=1/1";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *codecview = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&codecview, graph, "codecview", "codecview", "block=1") < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, codecview, 0) < 0 ||
        avfilter_link(codecview, 0, sink, 0) < 0 ||
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
            "frame=4x4 y_linesize=4 y_buffer_size=16 block=0,4+1x1\n");
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
