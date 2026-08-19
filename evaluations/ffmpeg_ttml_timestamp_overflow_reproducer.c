#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavutil/mem.h"

#ifndef TTMLENC_SOURCE
#define TTMLENC_SOURCE "libavformat/ttmlenc.c"
#endif
#include TTMLENC_SOURCE

int main(void)
{
    AVFormatContext format_context = { 0 };
    TTMLMuxContext private_context = {
        .input_type = PACKET_TYPE_PARAGRAPH,
    };
    AVPacket packet = { 0 };
    AVIOContext *io = NULL;
    uint8_t payload = 'x';

    if (avio_open_dyn_buf(&io) < 0)
        return 2;
    format_context.priv_data = &private_context;
    format_context.pb = io;
    packet.pts = INT64_MAX;
    packet.duration = 1;
    packet.data = &payload;
    packet.size = 1;

    fprintf(stderr,
            "pts=%lld duration=1 mathematical_end=9223372036854775808\n",
            (long long)packet.pts);
    fflush(stderr);
    int result = ttml_write_packet(&format_context, &packet);

#if defined(TTML_WRAP_REPLAY)
    uint8_t *output = NULL;
    int output_size = avio_close_dyn_buf(io, &output);
    int wrapped_negative_end =
        output_size > 0 && strstr((const char *)output, "end=\"-") != NULL;

    fprintf(stderr,
            "write_result=%d output_size=%d wrapped_negative_end=%d\n",
            result, output_size, wrapped_negative_end);
    av_free(output);
#endif
    return result;
}
