#include <stdio.h>

#include "libavformat/segafilmenc.c"

int main(void)
{
    AVFormatContext format = { 0 };
    AVStream stream = { 0 };
    AVCodecParameters parameters = { 0 };
    AVStream *streams[] = { &stream };
    AVPacket packet = { 0 };
    FILMOutputContext film = { 0 };

    parameters.codec_id = AV_CODEC_ID_CINEPAK;
    stream.codecpar = &parameters;
    format.streams = streams;
    format.nb_streams = 1;
    format.priv_data = &film;

    if (av_new_packet(&packet, 4) < 0)
        return 2;
    memset(packet.data, 0, packet.size);
    packet.stream_index = 0;

    fprintf(stderr,
            "packet_size=%d encoded_buf_size=0 modulo_divisor=0 "
            "cinepak=1\n",
            packet.size);
    fflush(stderr);

    return film_write_packet(&format, &packet);
}
