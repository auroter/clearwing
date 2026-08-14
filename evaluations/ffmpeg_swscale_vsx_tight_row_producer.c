#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libavutil/pixfmt.h"
#include "libswscale/swscale.h"

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

#define SOURCE_WIDTH 2
#define DESTINATION_WIDTH 3

int main(void)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    uint8_t *mapping = MAP_FAILED;
    const uint8_t *source_data[4] = { NULL };
    int source_stride[4] = { 0 };
    uint8_t destination[DESTINATION_WIDTH] = { 0 };
    uint8_t *destination_data[4] = { destination, NULL, NULL, NULL };
    int destination_stride[4] = { DESTINATION_WIDTH, 0, 0, 0 };
    struct SwsContext *context = NULL;
    uint8_t *source;
    int rows;

    if (page_size <= 0)
        return 2;
    mapping = mmap(NULL, (size_t)page_size * 2, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    if (mprotect(mapping + page_size, page_size, PROT_NONE) != 0)
        goto fail;

    source = mapping + page_size - SOURCE_WIDTH;
    source[0] = 16;
    source[1] = 240;
    source_data[0] = source;
    source_stride[0] = SOURCE_WIDTH;

    context = sws_getContext(SOURCE_WIDTH, 1, AV_PIX_FMT_GRAY8,
                             DESTINATION_WIDTH, 1, AV_PIX_FMT_GRAY8,
                             SWS_FAST_BILINEAR, NULL, NULL, NULL);
    if (!context)
        goto fail;

    fprintf(stderr,
            "public_sws_scale=1 source_width=%d destination_width=%d "
            "source_stride=%d guard_after_source=1 scaler=fast_bilinear\n",
            SOURCE_WIDTH, DESTINATION_WIDTH, source_stride[0]);
    fflush(stderr);
    rows = sws_scale(context, source_data, source_stride, 0, 1,
                     destination_data, destination_stride);
    fprintf(stderr, "unexpected_scale_rows=%d output=%u,%u,%u\n", rows,
            destination[0], destination[1], destination[2]);

    sws_freeContext(context);
    munmap(mapping, (size_t)page_size * 2);
    return rows == 1 ? 0 : 1;

fail:
    sws_freeContext(context);
    if (mapping != MAP_FAILED)
        munmap(mapping, (size_t)page_size * 2);
    return 2;
}
