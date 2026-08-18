#include <stdio.h>
#include <stdlib.h>

#ifndef VC1TESTENC_SOURCE
#define VC1TESTENC_SOURCE "libavformat/vc1testenc.c"
#endif
#include VC1TESTENC_SOURCE

int main(void)
{
    AVFormatContext format_context = { 0 };
    AVCodecParameters codec_parameters = { 0 };
    AVStream stream = { 0 };
    AVStream *streams[] = { &stream };
    AVIOContext *io = NULL;
    uint8_t *extradata = malloc(1);
    int (*volatile write_header)(AVFormatContext *) = vc1test_write_header;

    if (!extradata || avio_open_dyn_buf(&io) < 0)
        return 2;
    extradata[0] = 0;
    codec_parameters.codec_type = AVMEDIA_TYPE_VIDEO;
    codec_parameters.codec_id = AV_CODEC_ID_WMV3;
    codec_parameters.width = 16;
    codec_parameters.height = 16;
    codec_parameters.extradata = extradata;
    codec_parameters.extradata_size = 1;
    stream.codecpar = &codec_parameters;
    format_context.pb = io;
    format_context.streams = streams;
    format_context.nb_streams = 1;

    fprintf(stderr, "codec=wmv3 extradata_allocation=1 extradata_size=1\n");
    fflush(stderr);

    return write_header(&format_context);
}
