#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavutil/mem.h"

#ifndef HLSPLAYLIST_SOURCE
#define HLSPLAYLIST_SOURCE "libavformat/hlsplaylist.c"
#endif
#include HLSPLAYLIST_SOURCE

int main(void)
{
    AVIOContext *output = NULL;
    uint8_t *playlist = NULL;
    double program_date_time = 0x1.fffffffffffffp+62;
    int ret;

    ret = avio_open_dyn_buf(&output);
    if (ret < 0)
        return 2;

    fprintf(stderr,
            "program_date_time=%.0f int64_max=%lld localtime_range_check=absent\n",
            program_date_time, (long long)INT64_MAX);
    fflush(stderr);

    ret = ff_hls_write_file_entry(output, 0, 0, 1.0, 0, 0, 0,
                                  NULL, "segment.ts", &program_date_time,
                                  0, 0, 0);
    fprintf(stderr, "hls_entry_result=%d\n", ret);

    avio_close_dyn_buf(output, &playlist);
    av_free(playlist);
    return ret < 0;
}
