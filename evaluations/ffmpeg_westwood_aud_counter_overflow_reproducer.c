#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavutil/mem.h"

#ifndef WESTWOOD_AUDENC_SOURCE
#define WESTWOOD_AUDENC_SOURCE "libavformat/westwood_audenc.c"
#endif
#include WESTWOOD_AUDENC_SOURCE

static int discard_write(void *opaque, const uint8_t *buffer, int size)
{
    (void)opaque;
    (void)buffer;
    return size;
}

int main(void)
{
    const int packet_size = UINT16_MAX / 4;
    const int packet_count = 32771;
    AVFormatContext format_context = { 0 };
    AUDMuxContext private_context = { 0 };
    AVPacket packet = { 0 };
    uint8_t *io_buffer = av_malloc(4096);
    AVIOContext *io;
    uint8_t *payload = calloc(packet_size, 1);
    int result = 0;

    if (!payload || !io_buffer)
        return 2;
    io = avio_alloc_context(io_buffer, 4096, 1, NULL,
                            NULL, discard_write, NULL);
    if (!io)
        return 2;
    format_context.priv_data = &private_context;
    format_context.pb = io;
    packet.data = payload;
    packet.size = packet_size;

    for (int i = 0; i < packet_count; i++) {
        if (i == packet_count - 1) {
            fprintf(stderr,
                    "prior_packets=%d packet_size=%d prior_compressed=%d "
                    "prior_uncompressed=%d mathematical_uncompressed=%lld\n",
                    i, packet_size, private_context.size,
                    private_context.uncomp_size,
                    (long long)private_context.uncomp_size + packet_size * 4LL);
            fflush(stderr);
        }
        result = wsaud_write_packet(&format_context, &packet);
        if (result < 0)
            break;
    }
    fprintf(stderr,
            "write_result=%d compressed=%d uncompressed=%d\n",
            result, private_context.size, private_context.uncomp_size);
    avio_context_free(&io);
    free(payload);
    return result;
}
