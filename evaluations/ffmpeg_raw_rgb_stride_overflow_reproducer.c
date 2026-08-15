#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/codec_par.h"
#include "libavcodec/packet.h"
#include "libavformat/rawutils.c"

#define WIDTH 477218589
#define HEIGHT 3
#define BITS_PER_CODED_SAMPLE 24
#define EXPECTED_STRIDE 1431655768
#define SOURCE_STRIDE 72
#define SOURCE_SIZE (SOURCE_STRIDE * HEIGHT)
#define WRAPPED_DESTINATION_SIZE 8
#define PADDED_DESTINATION_SIZE 72
#define PADDING_WRITE_SIZE (EXPECTED_STRIDE - SOURCE_STRIDE)

int main(void)
{
    AVCodecParameters parameters = { 0 };
    AVPacket *packet = av_packet_alloc();
    AVPacket *original = packet;
    int64_t stride64;
    int expected_stride;
    int ret = 1;

    if (!packet || av_new_packet(packet, SOURCE_SIZE) < 0)
        goto done;
    memset(packet->data, 0xA5, packet->size);

    parameters.width = WIDTH;
    parameters.height = HEIGHT;
    parameters.bits_per_coded_sample = BITS_PER_CODED_SAMPLE;
    stride64 = (((int64_t)parameters.width *
                 parameters.bits_per_coded_sample + 31) >> 5) * 4;
    expected_stride = stride64;
    if (expected_stride != EXPECTED_STRIDE)
        goto done;

    fprintf(stderr,
            "raw_rgb_width=%d height=%d bpc=%d expected_stride=%d "
            "source_stride=%d source_size=%d wrapped_destination_size=%d "
            "padded_destination_size=%d padding_write_size=%d\n",
            WIDTH, HEIGHT, BITS_PER_CODED_SAMPLE, expected_stride,
            SOURCE_STRIDE, SOURCE_SIZE, WRAPPED_DESTINATION_SIZE,
            PADDED_DESTINATION_SIZE, PADDING_WRITE_SIZE);
    fflush(stderr);

    ret = ff_reshuffle_raw_rgb(NULL, &packet, &parameters, expected_stride);

done:
    if (packet != original)
        av_packet_free(&packet);
    av_packet_free(&original);
    return ret < 0 ? 1 : 0;
}
