#include <stdint.h>
#include <stdio.h>

#include "libavfilter/avfilter.h"
#include "libavutil/error.h"

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
        "time_base=1/48000:sample_rate=48000:sample_fmt=fltp:channel_layout=mono";
    const char *chorus_args =
        "delays=40|50:decays=0.4|0.3:speeds=1:depths=0.25|0.3";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *chorus = NULL;
    AVFilterContext *sink = NULL;
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
        avfilter_link(chorus, 0, sink, 0) < 0) {
        fprintf(stderr, "filter_link_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "delay_count=2 decay_count=2 speed_count=1 depth_count=2 "
            "chorus_creation_accepted=1\n");
    fflush(stderr);
    ret = avfilter_graph_config(graph, NULL);
    fprintf(stderr, "unexpected_graph_config_return=%d\n", ret);

done:
    avfilter_graph_free(&graph);
    return ret < 0 ? 2 : 0;
}
