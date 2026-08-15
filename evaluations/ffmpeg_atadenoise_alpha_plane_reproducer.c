#include <stdio.h>

#include "libavfilter/vf_atadenoise.c"

int main(void)
{
    ATADenoiseContext state = { 0 };
    AVFilterContext filter = { 0 };
    AVFrame *input = av_frame_alloc();
    AVFrame *output = av_frame_alloc();
    ThreadData thread_data;
    int ret = 2;

    if (!input || !output)
        goto done;
    input->format = output->format = AV_PIX_FMT_YUVA444P;
    input->width = output->width = 1;
    input->height = output->height = 1;
    if (av_frame_get_buffer(input, 0) < 0 ||
        av_frame_get_buffer(output, 0) < 0)
        goto done;

    state.size = 5;
    state.mid = 2;
    state.nb_planes = 4;
    state.planes = 1 << 3;
    for (int plane = 0; plane < 4; plane++) {
        state.planewidth[plane] = 1;
        state.planeheight[plane] = 1;
        state.linesizes[plane] = 1;
    }
    state.dsp.filter_row[3] = fweight_row8;
    filter.priv = &state;
    thread_data.in = input;
    thread_data.out = output;

    fprintf(stderr,
            "filter=atadenoise format=yuva444p planes=8 nb_planes=4 "
            "queue_size=5 alpha_data_entries_initialized=0\n");
    fflush(stderr);
    ret = filter_slice(&filter, &thread_data, 0, 1);

done:
    av_frame_free(&input);
    av_frame_free(&output);
    return ret;
}
