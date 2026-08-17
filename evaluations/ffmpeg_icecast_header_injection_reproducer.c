#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "libavformat/avio.h"
#include "libavformat/avformat.h"
#include "libavutil/dict.h"

int main(int argc, char **argv)
{
    AVDictionary *options = NULL;
    AVIOContext *io = NULL;
    char url[256];
    char *end = NULL;
    long port;
    int ret;

    if (argc != 2)
        return 2;

    errno = 0;
    port = strtol(argv[1], &end, 10);
    if (errno || !end || *end || port < 1 || port > 65535)
        return 2;

    snprintf(url, sizeof(url),
             "icecast://source:secret@127.0.0.1:%ld/mount", port);
    av_dict_set(&options, "ice_name", "safe-name\r\nX-Injected: yes", 0);
    av_dict_set(&options, "legacy_icecast", "1", 0);

    avformat_network_init();
    ret = avio_open2(&io, url, AVIO_FLAG_WRITE, NULL, &options);
    printf("entry=avio_open2 option=ice_name open_ret=%d\n", ret);
    fflush(stdout);
    if (ret >= 0)
        avio_closep(&io);
    av_dict_free(&options);
    avformat_network_deinit();
    return ret < 0;
}
