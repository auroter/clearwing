#include <stdint.h>
#include <stdio.h>

#include "libavformat/avformat.h"
#include "libavformat/rtpenc.h"
#include "libavutil/mem.h"

#define AAC_PACKET_SIZE 1
#define ADTS_HEADER_SIZE 7
#define RTP_BUFFER_SIZE 1200

void ff_rtp_send_data(AVFormatContext *s1, const uint8_t *buf, int len, int m)
{
    (void)s1;
    (void)buf;
    (void)len;
    (void)m;
}

#include "libavformat/rtpenc_aac.c"

int main(void)
{
    uint8_t *packet_data = av_mallocz(
        AAC_PACKET_SIZE + AV_INPUT_BUFFER_PADDING_SIZE
    );
    uint8_t *rtp_buffer = av_malloc(RTP_BUFFER_SIZE);
    AVCodecParameters codecpar = {
        .codec_type = AVMEDIA_TYPE_AUDIO,
        .codec_id = AV_CODEC_ID_AAC,
        .extradata_size = 0,
    };
    AVStream stream = {
        .codecpar = &codecpar,
        .time_base = { 1, 48000 },
    };
    AVStream *streams[] = { &stream };
    RTPMuxContext rtp = {
        .max_payload_size = RTP_BUFFER_SIZE,
        .max_frames_per_packet = 1,
        .buf = rtp_buffer,
        .buf_ptr = rtp_buffer,
    };
    AVFormatContext format = {
        .priv_data = &rtp,
        .nb_streams = 1,
        .streams = streams,
    };

    if (!packet_data || !rtp_buffer)
        return 1;

    fprintf(
        stderr,
        "aac_packet_size=%d adts_header_size=%d derived_payload_size=%d\n",
        AAC_PACKET_SIZE,
        ADTS_HEADER_SIZE,
        AAC_PACKET_SIZE - ADTS_HEADER_SIZE
    );
    fflush(stderr);
    ff_rtp_send_aac(&format, packet_data, AAC_PACKET_SIZE);

    av_free(rtp_buffer);
    av_free(packet_data);
    return 0;
}
