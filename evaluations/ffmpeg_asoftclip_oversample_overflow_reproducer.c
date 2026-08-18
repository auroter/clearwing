#include <stdint.h>
#include <stdio.h>

#include "libavutil/mem.h"
#include "libavutil/samplefmt.h"

#define av_frame_copy_props proof_av_frame_copy_props
#define av_frame_free proof_av_frame_free
#define av_frame_is_writable proof_av_frame_is_writable
#define ff_filter_execute proof_ff_filter_execute
#define ff_filter_frame proof_ff_filter_frame
#define ff_filter_get_nb_threads proof_ff_filter_get_nb_threads
#define ff_get_audio_buffer proof_ff_get_audio_buffer
#ifndef ASOFTCLIP_SOURCE
#define ASOFTCLIP_SOURCE "libavfilter/af_asoftclip.c"
#endif
#include ASOFTCLIP_SOURCE

static AVFrame output_frame;
static uint8_t *output_planes[1];
static int allocated_output_samples;
static int forwarded_output_samples;

int proof_av_frame_copy_props(AVFrame *dst, const AVFrame *src)
{
    (void)dst;
    (void)src;
    return 0;
}

void proof_av_frame_free(AVFrame **frame)
{
    *frame = NULL;
}

int proof_av_frame_is_writable(AVFrame *frame)
{
    (void)frame;
    return 0;
}

int proof_ff_filter_execute(AVFilterContext *ctx, avfilter_action_func *func,
                            void *arg, int *ret, int nb_jobs)
{
    int result = func(ctx, arg, 0, nb_jobs);

    if (ret)
        ret[0] = result;
    return result;
}

int proof_ff_filter_frame(AVFilterLink *link, AVFrame *frame)
{
    (void)link;
    forwarded_output_samples = frame->nb_samples;
    return 0;
}

int proof_ff_filter_get_nb_threads(AVFilterContext *ctx)
{
    (void)ctx;
    return 1;
}

AVFrame *proof_ff_get_audio_buffer(AVFilterLink *link, int nb_samples)
{
    (void)link;
    allocated_output_samples = nb_samples;
    output_planes[0] = av_mallocz((size_t)nb_samples * sizeof(float));
    if (!output_planes[0])
        return NULL;
    output_frame.nb_samples = nb_samples;
    output_frame.extended_data = output_planes;
    return &output_frame;
}

int main(void)
{
    const int channels = 1;
    const int nb_samples = 67108865;
    const int oversample = 64;
    const int wrapped_output_samples =
        (int32_t)((uint32_t)nb_samples * (uint32_t)oversample);
    const size_t source_bytes = (size_t)nb_samples * sizeof(float);
    const size_t output_bytes = (size_t)wrapped_output_samples * sizeof(float);
    float history0[2 * MAX_OVERSAMPLE] = { 0 };
    float history1[2 * MAX_OVERSAMPLE] = { 0 };
    uint8_t *history_data0[1] = { (uint8_t *)history0 };
    uint8_t *history_data1[1] = { (uint8_t *)history1 };
    AVFrame history_frame0 = { .extended_data = history_data0 };
    AVFrame history_frame1 = { .extended_data = history_data1 };
    ASoftClipContext softclip = {
        .type = ASC_HARD,
        .oversample = oversample,
        .threshold = 1.0,
        .output = 1.0,
        .param = 1.0,
        .frame = { &history_frame0, &history_frame1 },
        .filter = filter_flt,
    };
    float *src = av_malloc(source_bytes);
    uint8_t *src_planes[1] = { (uint8_t *)src };
    AVFrame input_frame = {
        .nb_samples = nb_samples,
        .extended_data = src_planes,
        .ch_layout = { .order = AV_CHANNEL_ORDER_UNSPEC, .nb_channels = channels },
    };
    AVFilterLink outlink = { .format = AV_SAMPLE_FMT_FLTP };
    AVFilterLink *outputs[1] = { &outlink };
    AVFilterContext context = {
        .outputs = outputs,
        .nb_outputs = 1,
        .priv = &softclip,
        .nb_threads = 1,
    };
    AVFilterLink inlink = {
        .dst = &context,
        .format = AV_SAMPLE_FMT_FLTP,
    };
    int input_buffer_check;
    int output_buffer_check;

    if (!src) {
        av_free(src);
        return 2;
    }
    src[0] = 0.25f;
    src[1] = 0.5f;
    input_buffer_check = av_samples_get_buffer_size(
        NULL, channels, nb_samples, AV_SAMPLE_FMT_FLTP, 1);
    output_buffer_check = av_samples_get_buffer_size(
        NULL, channels, wrapped_output_samples, AV_SAMPLE_FMT_FLTP, 1);

    fprintf(stderr,
            "channels=%d nb_samples=%d oversample=%d product=%lld "
            "wrapped_output_samples=%d input_bytes=%zu output_bytes=%zu "
            "input_buffer_check=%d output_buffer_check=%d\n",
            channels, nb_samples, oversample,
            (long long)nb_samples * oversample,
            wrapped_output_samples, source_bytes, output_bytes,
            input_buffer_check, output_buffer_check);
    fflush(stderr);
    fprintf(stderr, "calling_production_filter_frame=1\n");
    fflush(stderr);
    int filter_result = filter_frame(&inlink, &input_frame);
    fprintf(stderr,
            "filter_result=%d allocated_output_samples=%d "
            "forwarded_output_samples=%d\n",
            filter_result, allocated_output_samples, forwarded_output_samples);

    av_free(src);
    av_free(output_planes[0]);
    return 0;
}
