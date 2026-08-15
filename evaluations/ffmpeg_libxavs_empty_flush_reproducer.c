#include <stdio.h>
#include <string.h>

#include "libavcodec/libxavs.c"

struct xavs_t {
    int unused;
};

void xavs_param_default(xavs_param_t *params)
{
    memset(params, 0, sizeof(*params));
}

xavs_t *xavs_encoder_open(xavs_param_t *params)
{
    return (xavs_t *)params;
}

void xavs_encoder_close(xavs_t *encoder)
{
}

int xavs_encoder_encode(xavs_t *encoder, xavs_nal_t **nals, int *nnal,
                        xavs_picture_t *input, xavs_picture_t *output)
{
    *nals = NULL;
    *nnal = 0;
    return 0;
}

int xavs_encoder_headers(xavs_t *encoder, xavs_nal_t **nals, int *nnal)
{
    return 0;
}

int xavs_nal_encode(uint8_t *destination, int *size, int annexb,
                    xavs_nal_t *nal)
{
    return -1;
}

int main(void)
{
    AVCodecContext avctx = { 0 };
    AVPacket packet = { 0 };
    XavsContext x4 = { 0 };
    int got_packet = 0;

    avctx.priv_data = &x4;
    avctx.max_b_frames = 2;
    avctx.get_encode_buffer = avcodec_default_get_encode_buffer;
    x4.pts_buffer = av_calloc(avctx.max_b_frames + 1,
                              sizeof(*x4.pts_buffer));
    if (!x4.pts_buffer)
        return 2;

    fprintf(stderr,
            "empty_flush=1 out_frame_count=%d max_b_frames=%d "
            "first_index=%d second_index=%d\n",
            x4.out_frame_count, avctx.max_b_frames,
            (x4.out_frame_count - 1) % (avctx.max_b_frames + 1),
            (x4.out_frame_count - 2) % (avctx.max_b_frames + 1));
    fflush(stderr);

    return XAVS_frame(&avctx, &packet, NULL, &got_packet);
}
