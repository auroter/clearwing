#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "config_components.h"
#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavfilter/buffersrc.h"
#include "libavutil/frame.h"
#include "libavutil/pixfmt.h"

/* The configured checkout omits segment, so compile the production filter into
 * this public libavfilter graph harness. */
#undef CONFIG_SEGMENT_FILTER
#define CONFIG_SEGMENT_FILTER 1
#include "libavfilter/f_segment.c"

int main(void)
{
    const AVFilter *buffer = avfilter_get_by_name("buffer");
    const AVFilter *buffersink = avfilter_get_by_name("buffersink");
    AVFilterGraph *graph = NULL;
    AVFilterContext *source = NULL;
    AVFilterContext *segment = NULL;
    AVFilterContext *sinks[2] = { NULL };
    AVFrame *frame = NULL;
    AVFrame *output = NULL;
    int ret = 1;

    if (!buffer || !buffersink)
        goto done;
    graph = avfilter_graph_alloc();
    frame = av_frame_alloc();
    output = av_frame_alloc();
    if (!graph || !frame || !output)
        goto done;

    if (avfilter_graph_create_filter(
            &source, buffer, "source",
            "video_size=1x1:pix_fmt=gray:time_base=1/1:pixel_aspect=1/1",
            NULL, graph) < 0 ||
        avfilter_graph_create_filter(
            &segment, &ff_vf_segment.p, "segment", "timestamps=0", NULL,
            graph) < 0 ||
        avfilter_graph_create_filter(
            &sinks[0], buffersink, "sink0", NULL, NULL, graph) < 0 ||
        avfilter_graph_create_filter(
            &sinks[1], buffersink, "sink1", NULL, NULL, graph) < 0)
        goto done;

    if (segment->nb_outputs != 2 ||
        avfilter_link(source, 0, segment, 0) < 0 ||
        avfilter_link(segment, 0, sinks[0], 0) < 0 ||
        avfilter_link(segment, 1, sinks[1], 0) < 0 ||
        avfilter_graph_config(graph, NULL) < 0)
        goto done;

    frame->format = AV_PIX_FMT_GRAY8;
    frame->width = 1;
    frame->height = 1;
    frame->pts = INT64_MAX;
    if (av_frame_get_buffer(frame, 1) < 0)
        goto done;
    frame->data[0][0] = 0;

    fprintf(stderr,
            "filter=segment split_timestamp=0 sentinel=%" PRId64
            " frame_pts=%" PRId64 " points=2\n",
            INT64_MAX, frame->pts);
    fflush(stderr);

    if (av_buffersrc_add_frame_flags(source, frame,
                                     AV_BUFFERSRC_FLAG_KEEP_REF) < 0)
        goto done;
    ret = av_buffersink_get_frame(sinks[1], output);

done:
    av_frame_free(&output);
    av_frame_free(&frame);
    avfilter_graph_free(&graph);
    return ret < 0 ? 1 : 0;
}
