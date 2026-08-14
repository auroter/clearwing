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
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *concat = NULL;
    AVFilterContext *sink = NULL;
    char response[64] = { 0 };
    int first_ret;
    int second_ret;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "abuffer", "source",
                      "time_base=1/48000:sample_rate=48000:sample_fmt=fltp:channel_layout=mono") < 0 ||
        create_filter(&concat, graph, "concat", "concat", "n=1:v=0:a=1") < 0 ||
        create_filter(&sink, graph, "abuffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, concat, 0) < 0 ||
        avfilter_link(concat, 0, sink, 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "public_concat_graph=1 segments=1 outputs=1 inputs=1 commands=2\n");
    fflush(stderr);
    first_ret = avfilter_graph_send_command(graph, "concat", "next", "",
                                            response, sizeof(response), 0);
    fprintf(stderr, "first_next_return=%d\n", first_ret);
    fflush(stderr);
    second_ret = avfilter_graph_send_command(graph, "concat", "next", "",
                                             response, sizeof(response), 0);
    fprintf(stderr, "unexpected_second_next_return=%d\n", second_ret);
    ret = second_ret;

done:
    avfilter_graph_free(&graph);
    return ret < 0 ? 2 : 0;
}
