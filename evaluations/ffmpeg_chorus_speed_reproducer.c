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
#define MODULATION_SPEED 96000

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
    ((float *)frame->extended_data[0])[0] = 0.25f;
    return frame;
}

int main(void)
{
    const char *source_args =
        "time_base=1/48000:sample_rate=48000:sample_fmt=fltp:channel_layout=mono";
    const char *chorus_args =
        "delays=40:decays=0.4:speeds=96000:depths=0.25";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *chorus = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "abuffer", "source", source_args) < 0 ||
        create_filter(&chorus, graph, "chorus", "chorus", chorus_args) < 0 ||
        create_filter(&sink, graph, "abuffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, chorus, 0) < 0 ||
        avfilter_link(chorus, 0, sink, 0) < 0 ||
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
            "sample_rate=%d modulation_speed=%d lookup_length=0 nb_samples=1\n",
            SAMPLE_RATE, MODULATION_SPEED);
    fflush(stderr);
    if (av_buffersrc_add_frame_flags(source, input,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0)
        goto done;
    ret = av_buffersink_get_frame(sink, output);
    fprintf(stderr, "unexpected_filter_return=%d\n", ret);

done:
    av_frame_free(&input);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret < 0 ? 2 : 0;
}
