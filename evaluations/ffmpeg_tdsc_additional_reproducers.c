#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libavcodec/tdsc.c"

static void put_le16(uint8_t *dst, unsigned int value)
{
    dst[0] = value;
    dst[1] = value >> 8;
}

static void put_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = value;
    dst[1] = value >> 8;
    dst[2] = value >> 16;
    dst[3] = value >> 24;
}

static int run_jpeg_dimension_mismatch(void)
{
    AVFrame *destination = av_frame_alloc();
    uint8_t *y = av_malloc(1);
    uint8_t *u = av_malloc(1);
    uint8_t *v = av_malloc(1);
    int ret = 2;

    if (!destination || !y || !u || !v)
        goto done;
    destination->format = AV_PIX_FMT_BGR24;
    destination->width = 64;
    destination->height = 64;
    if (av_frame_get_buffer(destination, 0) < 0)
        goto done;
    y[0] = u[0] = v[0] = 128;

    fprintf(stderr,
            "tdsc_scenario=jpeg_dimension_mismatch jpeg_width=1 "
            "jpeg_height=1 tile_width=64 tile_height=64\n");
    fflush(stderr);
    tdsc_blit(destination->data[0], destination->linesize[0],
              y, 1, u, v, 1, 64, 64);
    ret = 0;

done:
    av_free(y);
    av_free(u);
    av_free(v);
    av_frame_free(&destination);
    return ret;
}

static int run_mono_cursor_stride(void)
{
    AVCodecContext avctx = { 0 };
    TDSCContext context = { 0 };
    uint8_t input[28] = { 0 };
    int ret;

    avctx.width = avctx.height = 64;
    avctx.priv_data = &context;
    put_le16(input + 0, 0);
    put_le16(input + 2, 0);
    put_le16(input + 4, 1);
    put_le16(input + 6, 2);
    put_le32(input + 8, CUR_FMT_MONO);
    bytestream2_init(&context.gbc, input, sizeof(input));

    fprintf(stderr,
            "tdsc_scenario=mono_cursor_stride cursor_width=1 "
            "cursor_height=2 stride=128 allocation=256\n");
    fflush(stderr);
    ret = tdsc_load_cursor(&avctx);
    av_freep(&context.cursor);
    return ret < 0 ? 1 : 0;
}

static int run_resize_stale_stride(void)
{
    AVFrame *destination = av_frame_alloc();
    uint8_t *y = NULL;
    uint8_t *u = NULL;
    uint8_t *v = NULL;
    int old_linesize;
    int ret = 2;

    if (!destination)
        goto done;
    destination->format = AV_PIX_FMT_BGR24;
    destination->width = 1;
    destination->height = 1;
    if (av_frame_get_buffer(destination, 0) < 0)
        goto done;
    old_linesize = destination->linesize[0];

    destination->width = 256;
    destination->height = 32;
    if (av_frame_get_buffer(destination, 0) < 0)
        goto done;

    y = av_mallocz(256 * 32);
    u = av_mallocz(256 * 32);
    v = av_mallocz(256 * 32);
    if (!y || !u || !v)
        goto done;

    fprintf(stderr,
            "tdsc_scenario=resize_stale_stride old_width=1 old_height=1 "
            "new_width=256 new_height=32 stale_linesize=%d "
            "allocation=%zu required_last_row=%d\n",
            old_linesize, destination->buf[0]->size,
            (32 - 1) * old_linesize + 256 * 3);
    fflush(stderr);
    tdsc_blit(destination->data[0], destination->linesize[0],
              y, 256, u, v, 256, 256, 32);
    ret = 0;

done:
    av_free(y);
    av_free(u);
    av_free(v);
    av_frame_free(&destination);
    return ret;
}

static int run_truncated_tile_disclosure(void)
{
    AVCodecContext avctx = { 0 };
    TDSCContext context = { 0 };
    uint8_t input[32] = { 0 };
    int disclosed = 1;
    int ret = 2;

    context.width = 8;
    context.height = 1;
    context.refframe = av_frame_alloc();
    if (!context.refframe)
        goto done;
    context.refframe->format = AV_PIX_FMT_BGR24;
    context.refframe->width = 8;
    context.refframe->height = 1;
    if (av_frame_get_buffer(context.refframe, 0) < 0)
        goto done;
    memset(context.refframe->data[0], 0, context.refframe->linesize[0]);
    avctx.priv_data = &context;

    put_le32(input + 0, MKTAG('T', 'D', 'S', 'B'));
    put_le32(input + 4, 24);
    put_le32(input + 8, MKTAG(' ', 'W', 'A', 'R'));
    put_le32(input + 12, 0);
    put_le32(input + 16, 0);
    put_le32(input + 20, 0);
    put_le32(input + 24, 8);
    put_le32(input + 28, 1);
    bytestream2_init(&context.gbc, input, sizeof(input));

    ret = tdsc_decode_tiles(&avctx, 1);
    if (ret < 0)
        goto done;
    for (int i = 0; i < 24; i++)
        disclosed &= context.refframe->data[0][i] == 0xA5;
    fprintf(stderr,
            "tdsc_scenario=truncated_tile_disclosure tile_size=24 "
            "header_bytes_after_size=24 payload_bytes=0 "
            "allocator_fill_observed=%d disclosed_bytes=24\n",
            disclosed);
    ret = disclosed ? 0 : 3;

done:
    av_freep(&context.tilebuffer);
    av_frame_free(&context.refframe);
    return ret;
}

static int run_cursor_position_overflow(void)
{
    AVCodecContext avctx = { 0 };
    TDSCContext context = { 0 };
    uint8_t *destination = av_mallocz(64 * 64 * 3);
    int ret = 2;

    context.width = context.height = 64;
    context.cursor = av_mallocz(4);
    if (!destination || !context.cursor)
        goto done;
    context.cursor[0] = 0xFF;
    context.cursor_stride = 4;
    context.cursor_w = context.cursor_h = 1;
    context.cursor_x = INT_MAX;
    context.cursor_y = 0;
    avctx.priv_data = &context;

    fprintf(stderr,
            "tdsc_scenario=cursor_position_overflow cursor_x=%d "
            "cursor_width=1 frame_width=64\n",
            context.cursor_x);
    fflush(stderr);
    tdsc_paint_cursor(&avctx, destination, 64 * 3);
    ret = 0;

done:
    av_free(destination);
    av_free(context.cursor);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 64;
    if (!strcmp(argv[1], "jpeg"))
        return run_jpeg_dimension_mismatch();
    if (!strcmp(argv[1], "cursor"))
        return run_mono_cursor_stride();
    if (!strcmp(argv[1], "resize"))
        return run_resize_stale_stride();
    if (!strcmp(argv[1], "truncated"))
        return run_truncated_tile_disclosure();
    if (!strcmp(argv[1], "position"))
        return run_cursor_position_overflow();
    return 64;
}
