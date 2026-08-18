#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libswscale/swscale_internal.h"

/* Emit the production x86 wrapper on this arm64 proof host. */
#undef ARCH_X86_64
#undef HAVE_SSSE3_EXTERNAL
#undef HAVE_X86ASM
#define ARCH_X86_64 1
#define HAVE_SSSE3_EXTERNAL 0
#define HAVE_X86ASM 1

#ifndef YUV2RGB_SOURCE
#define YUV2RGB_SOURCE "libswscale/x86/yuv2rgb.c"
#endif
#include YUV2RGB_SOURCE

#define MARKER 0xA5

static int assembly_pixels;

void ff_yuv_420_gbrp24_ssse3(x86_reg index, uint8_t *dst_g,
                             uint8_t *dst_b, uint8_t *dst_r,
                             const uint8_t *pu_index,
                             const uint8_t *pv_index,
                             const uint64_t *pointer_c_dither,
                             const uint8_t *py_2index)
{
    assembly_pixels = (int)(-2 * index);
    memset(dst_g, 0x11, assembly_pixels);
    memset(dst_b, 0x22, assembly_pixels);
    memset(dst_r, 0x33, assembly_pixels);
    (void)pu_index;
    (void)pv_index;
    (void)pointer_c_dither;
    (void)py_2index;
}

int main(void)
{
    const int width = 16;
    const int height = 1;
    SwsInternal context = { 0 };
    uint8_t src_y[32] = { 0 };
    uint8_t src_u[16] = { 0 };
    uint8_t src_v[16] = { 0 };
    uint8_t dst_g[16];
    uint8_t dst_b[16];
    uint8_t dst_r[16];
    const uint8_t *src[4] = { src_y, src_u, src_v, NULL };
    uint8_t *dst[4] = { dst_g, dst_b, dst_r, NULL };
    const int src_stride[4] = { width, width / 2, width / 2, 0 };
    const int dst_stride[4] = { width, width, width, 0 };
    int marker_bytes = 0;
    int result;

    memset(dst_g, MARKER, sizeof(dst_g));
    memset(dst_b, MARKER, sizeof(dst_b));
    memset(dst_r, MARKER, sizeof(dst_r));
    context.opts.dst_w = width;
    context.opts.src_format = AV_PIX_FMT_YUV420P;

    result = yuv420_gbrp_ssse3(&context, src, src_stride, 0, height,
                               dst, dst_stride);
    for (int i = 0; i < width; i++) {
        marker_bytes += dst_g[i] == MARKER;
        marker_bytes += dst_b[i] == MARKER;
        marker_bytes += dst_r[i] == MARKER;
    }

    fprintf(stderr,
            "width=%d height=%d stride=%d assembly_pixels=%d "
            "visible_marker_bytes=%d result=%d\n",
            width, height, dst_stride[0], assembly_pixels,
            marker_bytes, result);
    return result == height ? 0 : 2;
}
