#include <stdint.h>
#include <stdio.h>

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

static AVFrame *make_tight_frame(int64_t pts, uint8_t value)
{
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->buf[0] = av_buffer_alloc(1);
    if (!frame->buf[0]) {
        av_frame_free(&frame);
        return NULL;
    }
    frame->format = AV_PIX_FMT_GRAY8;
    frame->width = 1;
    frame->height = 1;
    frame->pts = pts;
    frame->data[0] = frame->buf[0]->data;
    frame->linesize[0] = 1;
    frame->data[0][0] = value;
    return frame;
}

int main(void)
{
    const char *hint_path = "/private/tmp/cw-fieldhint-odd-height-hints.txt";
    const char *source_args =
        "video_size=1x1:pix_fmt=gray:time_base=1/1:pixel_aspect=1/1";
    char fieldhint_args[512];
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *fieldhint = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *first = NULL;
    AVFrame *second = NULL;
    AVFrame *output = NULL;
    FILE *hint = NULL;
    int ret = 1;

    hint = fopen(hint_path, "w");
    if (!hint) {
        fprintf(stderr, "hint_creation_failed=1\n");
        return 2;
    }
    if (fputs("0,0\n", hint) < 0) {
        fclose(hint);
        remove(hint_path);
        fprintf(stderr, "hint_creation_failed=1\n");
        return 2;
    }
    if (fclose(hint) != 0) {
        remove(hint_path);
        fprintf(stderr, "hint_creation_failed=1\n");
        return 2;
    }
    hint = NULL;
    snprintf(fieldhint_args, sizeof(fieldhint_args),
             "hint=%s:mode=relative", hint_path);

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&fieldhint, graph, "fieldhint", "fieldhint",
                      fieldhint_args) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, fieldhint, 0) < 0 ||
        avfilter_link(fieldhint, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    first = make_tight_frame(0, 17);
    second = make_tight_frame(1, 34);
    output = av_frame_alloc();
    if (!first || !second || !output) {
        fprintf(stderr, "frame_allocation_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "input_width=1 input_height=1 linesize=1 buffer_size=1 "
            "bottom_copy_rows=1 bottom_source_offset=1\n");
    fflush(stderr);
    if (av_buffersrc_add_frame_flags(source, first,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0 ||
        av_buffersrc_add_frame_flags(source, second,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0 ||
        av_buffersink_get_frame(sink, output) < 0) {
        fprintf(stderr, "frame_processing_failed=1\n");
        goto done;
    }
    fprintf(stderr, "unexpected_filter_success=1\n");
    ret = 0;

done:
    remove(hint_path);
    av_frame_free(&first);
    av_frame_free(&second);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret;
}
