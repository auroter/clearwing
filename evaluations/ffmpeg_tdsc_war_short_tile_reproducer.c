#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/tdsc.c"

#define WIDTH 64
#define HEIGHT 64
#define TILE_SIZE 4
#define HEADER_SIZE 32

static void put_le32(uint8_t *dst, uint32_t value)
{
    dst[0] = value;
    dst[1] = value >> 8;
    dst[2] = value >> 16;
    dst[3] = value >> 24;
}

int main(void)
{
    AVCodecContext avctx = { 0 };
    TDSCContext context = { 0 };
    uint8_t input[HEADER_SIZE + TILE_SIZE] = { 0 };
    int ret = 1;

    context.width = WIDTH;
    context.height = HEIGHT;
    context.refframe = av_frame_alloc();
    if (!context.refframe)
        return 2;

    context.refframe->format = AV_PIX_FMT_BGR24;
    context.refframe->width = WIDTH;
    context.refframe->height = HEIGHT;
    if (av_frame_get_buffer(context.refframe, 0) < 0)
        goto done;

    avctx.priv_data = &context;

    put_le32(input + 0, MKTAG('T', 'D', 'S', 'B'));
    put_le32(input + 4, TILE_SIZE);
    put_le32(input + 8, MKTAG(' ', 'W', 'A', 'R'));
    put_le32(input + 12, 0);
    put_le32(input + 16, 0);
    put_le32(input + 20, 0);
    put_le32(input + 24, WIDTH);
    put_le32(input + 28, HEIGHT);
    memset(input + HEADER_SIZE, 0xA5, TILE_SIZE);
    bytestream2_init(&context.gbc, input, sizeof(input));

    fprintf(stderr,
            "codec=tdsc tile_mode=WAR width=%d height=%d tile_size=%d "
            "copy_bytes=%d first_row_read=%d\n",
            WIDTH, HEIGHT, TILE_SIZE, WIDTH * HEIGHT * 3, WIDTH * 3);
    fflush(stderr);

    ret = tdsc_decode_tiles(&avctx, 1);

done:
    av_freep(&context.tilebuffer);
    av_frame_free(&context.refframe);
    return ret < 0 ? 1 : 0;
}
