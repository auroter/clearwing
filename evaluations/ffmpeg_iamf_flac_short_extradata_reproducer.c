#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavutil/mem.h"

#include "libavformat/iamf_writer.c"

#define EXTRADATA_SIZE 12
#define REWRITE_SIZE 13

int main(void)
{
    uint8_t source[EXTRADATA_SIZE + AV_INPUT_BUFFER_PADDING_SIZE] = { 0 };
    AVCodecParameters codecpar = {
        .codec_id = AV_CODEC_ID_FLAC,
        .extradata_size = EXTRADATA_SIZE,
        .extradata = source,
        .sample_rate = 48000,
        .frame_size = 1024,
    };
    AVStream stream = { .codecpar = &codecpar };
    AVStream *streams[] = { &stream };
    AVStreamGroup stream_group = {
        .nb_streams = 1,
        .streams = streams,
    };
    IAMFContext iamf = { 0 };
    IAMFCodecConfig *codec_config = av_mallocz(sizeof(*codec_config));

    if (!codec_config)
        return 1;

    fprintf(stderr,
            "codec=flac source_padding=%d extradata_size=%d "
            "rewrite_size=%d duplicated_allocation_size=%d\n",
            AV_INPUT_BUFFER_PADDING_SIZE, codecpar.extradata_size,
            REWRITE_SIZE, EXTRADATA_SIZE);

    return fill_codec_config(&iamf, &stream_group, codec_config);
}
