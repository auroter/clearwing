#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/channel_layout.h"
#include "libavutil/error.h"
#include "libavutil/frame.h"
#include "libavutil/samplefmt.h"

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

int main(void)
{
    const char *source_args =
        "sample_rate=48000:sample_fmt=dblp:channel_layout=mono:time_base=1/48000";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *aeval = NULL;
    AVFilterContext *sink = NULL;
    AVFrame *input = av_frame_alloc();
    AVFrame *output = av_frame_alloc();
    int ret = 1;

    if (!graph || !input || !output)
        goto done;
    if (create_filter(&source, graph, "abuffer", "source", source_args) < 0 ||
        create_filter(&aeval, graph, "aeval", "aeval",
                      "exprs=val(-1):channel_layout=same") < 0 ||
        create_filter(&sink, graph, "abuffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, aeval, 0) < 0 ||
        avfilter_link(aeval, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    input->format = AV_SAMPLE_FMT_DBLP;
    input->sample_rate = 48000;
    input->nb_samples = 1;
    input->pts = 0;
    av_channel_layout_default(&input->ch_layout, 1);
    if (av_frame_get_buffer(input, 0) < 0)
        goto done;
    ((double *)input->extended_data[0])[0] = 0.25;

    fprintf(stderr,
            "aeval_expression=val(-1) input_channels=1 "
            "channel_values_allocation=8\n");
    fflush(stderr);
    if (av_buffersrc_add_frame_flags(source, input,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0)
        goto done;
    if (av_buffersink_get_frame(sink, output) < 0)
        goto done;

    fprintf(stderr, "unexpected_success=1 sample=%f\n",
            ((double *)output->extended_data[0])[0]);
    ret = 0;

done:
    av_frame_free(&input);
    av_frame_free(&output);
    avfilter_graph_free(&graph);
    return ret;
}
