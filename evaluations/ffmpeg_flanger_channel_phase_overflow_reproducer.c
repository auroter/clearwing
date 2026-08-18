#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(FLANGER_GUARDED_REPLAY)
#include <sanitizer/asan_interface.h>
#endif

#ifndef FLANGER_SOURCE
#define FLANGER_SOURCE "libavfilter/af_flanger.c"
#endif
#define ff_filter_frame proof_filter_frame
#include FLANGER_SOURCE
#undef ff_filter_frame

int proof_filter_frame(AVFilterLink *link, AVFrame *frame)
{
    av_frame_free(&frame);
    return 0;
}

int main(void)
{
    const int channels = 561;
    const int sample_rate = 384000;
    FlangerContext flanger = {
        .delay_min = 0.0,
        .delay_depth = 0.002,
        .feedback_gain = 0.0,
        .delay_gain = 0.0,
        .speed = 0.1,
        .channel_phase = 1.0,
        .wave_shape = WAVE_SIN,
        .interpolation = INTERPOLATION_LINEAR,
        .in_gain = 1.0,
    };
    AVFilterLink output_link = { 0 };
    AVFilterLink *outputs[] = { &output_link };
    AVFilterContext filter_context = {
        .priv = &flanger,
        .outputs = outputs,
    };
    AVFilterLink input_link = {
        .dst = &filter_context,
        .format = AV_SAMPLE_FMT_DBLP,
        .sample_rate = sample_rate,
        .ch_layout = {
            .order = AV_CHANNEL_ORDER_UNSPEC,
            .nb_channels = channels,
        },
    };
    AVFrame *frame = av_frame_alloc();
#if defined(FLANGER_GUARDED_REPLAY)
    float *guarded_lfo;
    const int64_t mathematical_product = (int64_t)(channels - 1) * 3840000;
    const int32_t wrapped_product = (int32_t)(uint32_t)mathematical_product;
    const int wrapped_index = wrapped_product % 3840000;
    const size_t guard_samples = (size_t)-wrapped_index + 16;
#endif
    int ret;

    if (!frame)
        return 2;

    ret = config_input(&input_link);
    if (ret < 0)
        return 3;

#if defined(FLANGER_GUARDED_REPLAY)
    guarded_lfo = av_malloc_array(guard_samples + flanger.lfo_length,
                                  sizeof(*guarded_lfo));
    if (!guarded_lfo)
        return 6;
    memcpy(guarded_lfo + guard_samples, flanger.lfo,
           flanger.lfo_length * sizeof(*guarded_lfo));
    av_free(flanger.lfo);
    flanger.lfo = guarded_lfo + guard_samples;
    __asan_poison_memory_region(guarded_lfo,
                                guard_samples * sizeof(*guarded_lfo));
    fprintf(stderr,
            "guarded_replay mathematical_product=%lld wrapped_product=%d "
            "wrapped_index=%d guard_samples=%zu\n",
            (long long)mathematical_product, wrapped_product, wrapped_index,
            guard_samples);
#endif

    frame->format = AV_SAMPLE_FMT_DBLP;
    frame->sample_rate = sample_rate;
    frame->nb_samples = 1;
    frame->ch_layout.order = AV_CHANNEL_ORDER_UNSPEC;
    frame->ch_layout.nb_channels = channels;
    ret = av_frame_get_buffer(frame, 0);
    if (ret < 0)
        return 4;

    fprintf(stderr,
            "channels=%d sample_rate=%d speed=0.1 lfo_length=%d "
            "first_overflow_channel=560\n",
            channels, sample_rate, flanger.lfo_length);
    fflush(stderr);

    ret = filter_frame(&input_link, frame);
    fprintf(stderr, "filter_result=%d\n", ret);
#if defined(FLANGER_GUARDED_REPLAY)
    __asan_unpoison_memory_region(guarded_lfo,
                                  guard_samples * sizeof(*guarded_lfo));
    flanger.lfo = guarded_lfo;
#endif
    uninit(&filter_context);
    return ret < 0;
}
