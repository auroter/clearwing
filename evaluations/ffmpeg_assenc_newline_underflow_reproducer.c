#include <stdio.h>

#include "libavformat/assenc.c"

int main(void)
{
    AVFormatContext format = { 0 };
    AVPacket packet = { 0 };
    ASSContext ass = { 0 };
    int ret;

    format.priv_data = &ass;
    if (av_new_packet(&packet, 1) < 0)
        return 2;
    packet.data[0] = '\n';
    packet.pts = 0;
    packet.duration = 1;

    fprintf(stderr,
            "packet_size=%d text_offset=0 initial_text_len=1 "
            "expected_final_text_len=0 underflow_index=-1\n",
            packet.size);
    fflush(stderr);

    ret = write_packet(&format, &packet);
    av_packet_unref(&packet);
    return ret;
}
