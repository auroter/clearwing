#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/codec2.c"

int av_get_packet(AVIOContext *s, AVPacket *pkt, int size)
{
    (void)s;
    (void)pkt;
    return size;
}

int main(int argc, char **argv)
{
    Codec2Context private_context = { 0 };
    AVCodecParameters codec_parameters = { 0 };
    AVStream stream = { 0 };
    AVStream *streams[] = { &stream };
    AVFormatContext format_context = { 0 };
    AVPacket packet = { 0 };

    if (argc != 2)
        return 2;

    format_context.priv_data = &private_context;
    format_context.streams = streams;
    stream.codecpar = &codec_parameters;

    if (!strcmp(argv[1], "packet-size")) {
        private_context.frames_per_packet = INT_MAX;
        codec_parameters.block_align = 8;
        codec_parameters.frame_size = 160;
    } else if (!strcmp(argv[1], "duration")) {
        private_context.frames_per_packet = 6710887;
        codec_parameters.block_align = 4;
        codec_parameters.frame_size = 320;
    } else {
        return 2;
    }

    fprintf(stderr,
            "case=%s frames_per_packet=%d block_align=%d frame_size=%d "
            "mathematical_packet_size=%lld mathematical_duration=%lld\n",
            argv[1], private_context.frames_per_packet,
            codec_parameters.block_align, codec_parameters.frame_size,
            (long long)private_context.frames_per_packet * codec_parameters.block_align,
            (long long)private_context.frames_per_packet * codec_parameters.frame_size);
    fflush(stderr);

    return codec2_read_packet(&format_context, &packet);
}
