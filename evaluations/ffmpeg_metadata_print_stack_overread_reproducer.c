#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/dict.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

#define METADATA_VALUE_LENGTH 511
#define FORMATTED_LENGTH 523
#define PRINT_BUFFER_SIZE 128

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

static AVFrame *make_input(void)
{
    char metadata_value[METADATA_VALUE_LENGTH + 1];
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    memset(metadata_value, 'X', METADATA_VALUE_LENGTH);
    metadata_value[METADATA_VALUE_LENGTH] = '\0';
    frame->format = AV_PIX_FMT_GRAY8;
    frame->width = 1;
    frame->height = 1;
    frame->pts = 0;
    frame->duration = 1;
    if (av_frame_get_buffer(frame, 0) < 0 ||
        av_dict_set(&frame->metadata, "sourcehunt", metadata_value, 0) < 0) {
        av_frame_free(&frame);
        return NULL;
    }
    return frame;
}

int main(int argc, char **argv)
{
    const char *source_args =
        "video_size=1x1:pix_fmt=gray:time_base=1/1:pixel_aspect=1/1";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *metadata = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    char metadata_args[1024];
    int ret = 1;

    if (argc != 2 || !graph)
        return 2;
    if (snprintf(metadata_args, sizeof(metadata_args),
                 "mode=print:file=%s", argv[1]) >= sizeof(metadata_args)) {
        fprintf(stderr, "metadata_path_too_long=1\n");
        goto done;
    }
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&metadata, graph, "metadata", "metadata",
                      metadata_args) < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, metadata, 0) < 0 ||
        avfilter_link(metadata, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    input = make_input();
    output = av_frame_alloc();
    if (!input || !output) {
        fprintf(stderr, "frame_allocation_failed=1\n");
        goto done;
    }
    fprintf(stderr,
            "metadata_value_length=%d formatted_length=%d "
            "stack_buffer_size=%d\n",
            METADATA_VALUE_LENGTH, FORMATTED_LENGTH, PRINT_BUFFER_SIZE);
    fflush(stderr);
    if (av_buffersrc_add_frame(source, input) < 0 ||
        av_buffersink_get_frame(sink, output) < 0) {
        fprintf(stderr, "frame_processing_failed=1\n");
        goto done;
    }

    fprintf(stderr, "frame_processed_without_asan=1\n");
    ret = 0;

done:
    av_frame_free(&input);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret;
}
