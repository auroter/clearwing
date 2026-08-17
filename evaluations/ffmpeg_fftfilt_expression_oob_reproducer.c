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
        "video_size=16x16:pix_fmt=yuv420p:time_base=1/1:pixel_aspect=1/1";
    AVFilterGraph *graph = avfilter_graph_alloc();
    AVFilterContext *source = NULL;
    AVFilterContext *fftfilt = NULL;
    AVFilterContext *sink = NULL;
    int ret = 1;

    if (!graph)
        return 2;
    if (create_filter(&source, graph, "buffer", "source", source_args) < 0 ||
        create_filter(&fftfilt, graph, "fftfilt", "fftfilt",
                      "weight_Y=weight_Y(100,0)") < 0 ||
        create_filter(&sink, graph, "buffersink", "sink", NULL) < 0) {
        fprintf(stderr, "filter_creation_failed=1\n");
        goto done;
    }
    if (avfilter_link(source, 0, fftfilt, 0) < 0 ||
        avfilter_link(fftfilt, 0, sink, 0) < 0) {
        fprintf(stderr, "filter_link_failed=1\n");
        goto done;
    }

    fprintf(stderr,
            "input_width=16 input_height=16 expression=weight_Y(100,0) "
            "unchecked_lut_coordinates=1\n");
    fflush(stderr);
    if (avfilter_graph_config(graph, NULL) < 0) {
        fprintf(stderr, "graph_configuration_failed=1\n");
        goto done;
    }
    fprintf(stderr, "unexpected_configuration_success=1\n");
    ret = 0;

done:
    avfilter_graph_free(&graph);
    return ret;
}
