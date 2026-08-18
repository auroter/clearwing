#include <stdio.h>

#include "libavutil/channel_layout.h"
#include "libavutil/opt.h"
#include "libavutil/samplefmt.h"
#include "libswresample/swresample.h"

int main(void)
{
    AVChannelLayout mono = AV_CHANNEL_LAYOUT_MONO;
    SwrContext *swr = NULL;
    int ret;

    ret = swr_alloc_set_opts2(&swr,
                              &mono, AV_SAMPLE_FMT_S32, 48000,
                              &mono, AV_SAMPLE_FMT_S32, 48000,
                              0, NULL);
    if (ret < 0 || !swr)
        return 2;
    if (av_opt_set_int(swr, "output_sample_bits", 33, 0) < 0) {
        swr_free(&swr);
        return 2;
    }

    fprintf(stderr,
            "api=swr_alloc_set_opts2 format=s32 output_sample_bits=33 "
            "declared_option_range=0..64 shift_exponent=-1\n");
    fflush(stderr);
    ret = swr_init(swr);
    fprintf(stderr, "unexpected_swr_init_return=%d\n", ret);
    swr_free(&swr);
    return ret < 0;
}
