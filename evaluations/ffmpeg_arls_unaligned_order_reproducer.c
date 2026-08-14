#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/channel_layout.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/samplefmt.h"

#define SAMPLE_RATE 48000
#define FILTER_ORDER 17
#define KERNEL_SIZE 32
#define INITIAL_OFFSET (KERNEL_SIZE - 1)
#define FIRST_COEFFICIENT_INDEX (FILTER_ORDER - INITIAL_OFFSET)

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

static AVFrame *make_frame(float sample)
{
    AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
    AVFrame *frame = av_frame_alloc();

    if (!frame)
        return NULL;
    frame->format = AV_SAMPLE_FMT_FLTP;
    frame->sample_rate = SAMPLE_RATE;
    frame->nb_samples = 1;
    frame->pts = 0;
    if (av_channel_layout_copy(&frame->ch_layout, &mono) < 0 ||
        av_frame_get_buffer(frame, 0) < 0) {
        av_frame_free(&frame);
        return NULL;
    }
    ((float *)frame->extended_data[0])[0] = sample;
    return frame;
}

int main(void)
{
    const char *source_args =
        "time_base=1/48000:sample_rate=48000:sample_fmt=fltp:channel_layout=mono";
    const char *arls_args = "order=17:precision=float";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *input_source = NULL;
    AVFilterContext *desired_source = NULL;
    AVFilterContext *arls = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *desired = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&input_source, graph, "abuffer", "input", source_args) < 0 ||
        create_filter(&desired_source, graph, "abuffer", "desired", source_args) < 0 ||
        create_filter(&arls, graph, "arls", "arls", arls_args) < 0 ||
        create_filter(&sink, graph, "abuffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(input_source, 0, arls, 0) < 0 ||
        avfilter_link(desired_source, 0, arls, 1) < 0 ||
        avfilter_link(arls, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }
    input = make_frame(0.25f);
    desired = make_frame(0.5f);
    output = av_frame_alloc();
    if (!input || !desired || !output) {
        fprintf(stderr, "frame_allocation_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "public_arls_graph=1 order=%d kernel_size=%d initial_offset=%d "
            "first_coefficient_index=%d nb_samples=1\n",
            FILTER_ORDER, KERNEL_SIZE, INITIAL_OFFSET,
            FIRST_COEFFICIENT_INDEX);
    fflush(stderr);
    if (av_buffersrc_add_frame_flags(input_source, input,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0 ||
        av_buffersrc_add_frame_flags(desired_source, desired,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0)
        goto done;
    ret = av_buffersink_get_frame(sink, output);
    fprintf(stderr, "unexpected_filter_return=%d\n", ret);

done:
    av_frame_free(&input);
    av_frame_free(&desired);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret < 0 ? 2 : 0;
}
