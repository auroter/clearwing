#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavformat/avio.h"
#include "libavformat/rtpdec.h"
#include "libavutil/error.h"

/* This proof never parses SDP or finalizes a marker-terminated frame. */
int ff_parse_fmtp(AVFormatContext *s, AVStream *stream, PayloadContext *data,
                  const char *p,
                  int (*parse_fmtp)(AVFormatContext *, AVStream *,
                                    PayloadContext *, const char *,
                                    const char *))
{
    return AVERROR(ENOSYS);
}

int ff_rtp_finalize_packet(AVPacket *pkt, AVIOContext **dyn_buf,
                           int stream_idx)
{
    return AVERROR(ENOSYS);
}

/* Include the production static payload handler in this translation unit. */
#include "libavformat/rtpdec_dv.c"

#define FRAGMENT_COUNT 4096
#define FRAGMENT_SIZE 2048

int main(void)
{
    AVFormatContext *format = avformat_alloc_context();
    AVPacket *packet = av_packet_alloc();
    PayloadContext payload = { 0 };
    uint8_t fragment[FRAGMENT_SIZE];
    uint8_t *buffer = NULL;
    uint32_t timestamp = 7;
    AVStream *stream;
    int buffered;

    if (!format || !packet)
        return 2;
    stream = avformat_new_stream(format, NULL);
    if (!stream)
        return 2;
    memset(fragment, 0x41, sizeof(fragment));

    for (int i = 0; i < FRAGMENT_COUNT; i++) {
        int ret = dv_handle_packet(format, &payload, stream, packet,
                                   &timestamp, fragment, sizeof(fragment),
                                   i, 0);
        if (ret != AVERROR(EAGAIN)) {
            fprintf(stderr, "unexpected_return=%d fragment=%d\n", ret, i);
            return 3;
        }
    }

    buffered = avio_get_dyn_buf(payload.buf, &buffer);
    fprintf(stderr,
            "fragments=%d fragment_size=%d marker_bits=0 timestamp=%u "
            "buffered_bytes=%d expected_bytes=%d output_packets=0\n",
            FRAGMENT_COUNT, FRAGMENT_SIZE, timestamp, buffered,
            FRAGMENT_COUNT * FRAGMENT_SIZE);

    dv_close_context(&payload);
    av_packet_free(&packet);
    avformat_free_context(format);
    return buffered == FRAGMENT_COUNT * FRAGMENT_SIZE ? 0 : 1;
}
