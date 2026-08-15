#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include "libavcodec/rscc.c"

int main(void)
{
    AVCodecContext *avctx = avcodec_alloc_context3(&ff_rscc_decoder.p);
    AVFrame *frame = av_frame_alloc();
    AVPacket packet = { 0 };
    RsccContext *rscc;
    uint8_t raw[4] = { 0 };
    uint8_t compressed[32];
    uLongf compressed_size = sizeof(compressed);
    uint8_t *p;
    int got_frame = 0;
    int marker_count = 0;
    int ret;

    if (!avctx || !frame)
        return 2;
    avctx->width = 2;
    avctx->height = 2;
    avctx->codec_tag = MKTAG('R', 'S', 'C', 'C');
    avctx->bits_per_coded_sample = 32;
    avctx->discard_damaged_percentage = 0;
    if (avcodec_open2(avctx, &ff_rscc_decoder.p, NULL) < 0)
        return 3;

    rscc = avctx->priv_data;
    memset(rscc->inflated_buf, 0xA5, rscc->inflated_size);
    if (compress2(compressed, &compressed_size, raw, sizeof(raw),
                  Z_BEST_SPEED) != Z_OK)
        return 4;
    if (compressed_size > 255 ||
        av_new_packet(&packet, 11 + compressed_size) < 0)
        return 5;
    p = packet.data;
    AV_WL16(p + 0, 1);
    AV_WL16(p + 2, 0);
    AV_WL16(p + 4, 2);
    AV_WL16(p + 6, 0);
    AV_WL16(p + 8, 2);
    p[10] = compressed_size;
    memcpy(p + 11, compressed, compressed_size);

    fprintf(stderr,
            "width=2 height=2 pixel_size=16 inflated_len=4 stale_bytes=12 "
            "compressed_size=%lu marker=0xA5\n",
            compressed_size);
    fflush(stderr);

    ret = rscc_decode_frame(avctx, frame, &got_frame, &packet);
    if (ret < 0 || !got_frame)
        return 6;
    for (int y = 0; y < 2; y++)
        for (int x = 0; x < 8; x++)
            marker_count +=
                frame->data[0][y * frame->linesize[0] + x] == 0xA5;

    fprintf(stderr, "decoded_marker_bytes=%d got_frame=%d\n",
            marker_count, got_frame);
    return marker_count == 12 ? 0 : 7;
}
