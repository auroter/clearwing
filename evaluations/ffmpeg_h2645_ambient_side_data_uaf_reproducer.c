#include <stdio.h>
#include <stdlib.h>

#ifndef H2645_SEI_SOURCE
#define H2645_SEI_SOURCE "libavcodec/h2645_sei.c"
#endif
#define ff_frame_new_side_data_from_buf_ext proof_preferred_side_data_consumer
#include H2645_SEI_SOURCE
#undef ff_frame_new_side_data_from_buf_ext

/*
 * Exact helper behavior when container-provided side data of this type is
 * already present and side_data_prefer_packet selects it: consume the new
 * buffer without attaching it.
 */
int proof_preferred_side_data_consumer(const AVCodecContext *avctx,
                                       AVFrameSideData ***sd, int *nb_sd,
                                       enum AVFrameSideDataType type,
                                       AVBufferRef **buf)
{
    av_buffer_unref(buf);
    return 0;
}

int main(void)
{
    AVCodecContext avctx = { 0 };
    H2645SEI sei = { 0 };
    AVFrameSideData **side_data = NULL;
    int nb_side_data = 1;

    sei.ambient_viewing_environment.present = 1;
    sei.ambient_viewing_environment.ambient_illuminance = 100;
    sei.ambient_viewing_environment.ambient_light_x = 200;
    sei.ambient_viewing_environment.ambient_light_y = 300;

    fprintf(stderr,
            "ambient_present=1 existing_packet_side_data=1 "
            "prefer_packet=1 helper_consumes_new_buffer=1\n");
    fflush(stderr);

    return h2645_sei_to_side_data(&avctx, &sei, &side_data, &nb_side_data);
}
