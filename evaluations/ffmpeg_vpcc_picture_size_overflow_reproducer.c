#include <stdio.h>

#ifndef VPCC_SOURCE
#define VPCC_SOURCE "libavformat/vpcc.c"
#endif
#include VPCC_SOURCE

int main(void)
{
    AVCodecParameters parameters = { 0 };
    VPCC vpcc = { 0 };
    int ret;

    parameters.codec_type = AVMEDIA_TYPE_VIDEO;
    parameters.codec_id = AV_CODEC_ID_VP9;
    parameters.width = 65535;
    parameters.height = 65535;
    parameters.profile = AV_PROFILE_UNKNOWN;
    parameters.level = AV_LEVEL_UNKNOWN;
    parameters.format = AV_PIX_FMT_YUV420P;
    parameters.chroma_location = AVCHROMA_LOC_LEFT;
    parameters.color_range = AVCOL_RANGE_MPEG;

    fprintf(stderr,
            "width=%d height=%d mathematical_picture_size=%lld "
            "positive_mux_dimensions=1\n",
            parameters.width, parameters.height,
            (long long)parameters.width * parameters.height);
    fflush(stderr);

    ret = ff_isom_get_vpcc_features(NULL, &parameters, NULL, 0, NULL, &vpcc);
    fprintf(stderr, "vpcc_result=%d level=%d\n", ret, vpcc.level);
    return ret < 0;
}
