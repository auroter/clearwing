#include <limits.h>
#include <stdint.h>
#include <stdio.h>

#ifndef SRTENC_SOURCE
#define SRTENC_SOURCE "libavformat/srtenc.c"
#endif
#include SRTENC_SOURCE

int main(void)
{
    AVFormatContext format_context = { 0 };
    SRTContext private_context = { 0 };
    AVPacket packet = { 0 };
    AVIOContext *io = NULL;
    uint8_t payload = 'x';

    if (avio_open_dyn_buf(&io) < 0)
        return 2;
    private_context.index = 1;
    format_context.priv_data = &private_context;
    format_context.pb = io;
    packet.pts = INT64_MAX;
    packet.duration = 1;
    packet.data = &payload;
    packet.size = 1;

    fprintf(stderr, "pts=%lld duration=1 mathematical_end=9223372036854775808\n",
            (long long)packet.pts);
    fflush(stderr);

    return srt_write_packet(&format_context, &packet);
}
