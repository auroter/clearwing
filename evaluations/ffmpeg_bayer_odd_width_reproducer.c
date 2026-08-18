#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "libavutil/pixfmt.h"
#include "libswscale/swscale.h"

#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

#define WIDTH 3
#define HEIGHT 2
#define SOURCE_SIZE (WIDTH * HEIGHT)
#define DESTINATION_STRIDE (WIDTH * 3)
#define DESTINATION_SIZE (DESTINATION_STRIDE * HEIGHT)

static uint8_t *guarded_tail(size_t size)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    uint8_t *mapping;

    if (page_size <= 0 || size > (size_t)page_size)
        return NULL;
    mapping = mmap(NULL, (size_t)page_size * 2,
                   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mapping == MAP_FAILED)
        return NULL;
    if (mprotect(mapping + page_size, (size_t)page_size, PROT_NONE) != 0)
        return NULL;
    return mapping + page_size - size;
}

int main(int argc, char **argv)
{
    const int guard_source = argc == 2 && !strcmp(argv[1], "source");
    const int guard_destination = argc == 2 && !strcmp(argv[1], "destination");
    const uint8_t *source_data[4] = { NULL };
    int source_stride[4] = { WIDTH, 0, 0, 0 };
    uint8_t *destination_data[4] = { NULL };
    int destination_stride[4] = { DESTINATION_STRIDE, 0, 0, 0 };
    struct SwsContext *context = NULL;
    uint8_t *source;
    uint8_t *destination;
    int rows;

    if (!guard_source && !guard_destination) {
        fprintf(stderr, "usage: %s source|destination\n", argv[0]);
        return 2;
    }

    source = guard_source ? guarded_tail(SOURCE_SIZE)
                          : calloc(1, SOURCE_SIZE + 64);
    destination = guard_destination ? guarded_tail(DESTINATION_SIZE)
                                    : calloc(1, DESTINATION_SIZE + 64);
    if (!source || !destination)
        return 2;
    memset(source, 0x5a, SOURCE_SIZE);
    memset(destination, 0, DESTINATION_SIZE);
    source_data[0] = source;
    destination_data[0] = destination;

    context = sws_getContext(WIDTH, HEIGHT, AV_PIX_FMT_BAYER_BGGR8,
                             WIDTH, HEIGHT, AV_PIX_FMT_RGB24,
                             SWS_POINT, NULL, NULL, NULL);
    if (!context) {
        fprintf(stderr, "odd_bayer_width_rejected=1\n");
        return 3;
    }

    fprintf(stderr,
            "public_sws_scale=1 width=%d height=%d source_stride=%d "
            "destination_stride=%d guarded=%s exact_size=1\n",
            WIDTH, HEIGHT, source_stride[0], destination_stride[0],
            guard_source ? "source" : "destination");
    fflush(stderr);
    rows = sws_scale(context, source_data, source_stride, 0, HEIGHT,
                     destination_data, destination_stride);
    fprintf(stderr, "unexpected_scale_rows=%d\n", rows);
    sws_freeContext(context);
    return rows == HEIGHT ? 0 : 4;
}
