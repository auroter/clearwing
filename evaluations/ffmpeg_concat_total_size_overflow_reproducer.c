#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "libavformat/avio.h"

#define NODE_SIZE INT64_C(9000000000000000000)

int main(int argc, char **argv)
{
    AVIOContext *io = NULL;
    char url[4096];
    int ret;

    if (argc != 2) {
        fprintf(stderr, "usage: %s tiny-seekable-file\n", argv[0]);
        return 2;
    }

    ret = snprintf(url, sizeof(url),
                   "concat:"
                   "subfile,,start,0,end,9000000000000000000,,:%.1800s"
                   "|"
                   "subfile,,start,0,end,9000000000000000000,,:%.1800s",
                   argv[1], argv[1]);
    if (ret < 0 || ret >= sizeof(url))
        return 2;

    fprintf(stderr,
            "protocol=concat nodes=2 node_size=%" PRId64
            " mathematical_total=18000000000000000000\n",
            NODE_SIZE);
    fflush(stderr);

    ret = avio_open2(&io, url, AVIO_FLAG_READ, NULL, NULL);
    fprintf(stderr, "unexpected_open_return=%d\n", ret);
    if (ret >= 0) {
        fprintf(stderr, "unexpected_reported_size=%" PRId64 "\n",
                avio_size(io));
        avio_closep(&io);
    }
    return ret < 0 ? 2 : 0;
}
