#include <stdio.h>
#include <stdlib.h>

#include "libavformat/avformat.h"
#include "libavformat/avio.h"
#include "libavutil/error.h"

int main(int argc, char **argv)
{
    AVIOContext *io = NULL;
    char url[4096];
    int port;
    int ret;

    if (argc != 3)
        return 2;
    port = atoi(argv[1]);
    if (port < 1 || port > 65535)
        return 2;
    if (snprintf(url, sizeof(url),
                 "dtls://localhost:%d?verify=1&cafile=%s&mtu=1200",
                 port, argv[2]) >= (int)sizeof(url))
        return 2;

    avformat_network_init();
    fprintf(stderr,
            "protocol=dtls target=localhost verify=1 "
            "certificate_dns_identity=wrong.example\n");
    fflush(stderr);
    ret = avio_open2(&io, url, AVIO_FLAG_READ_WRITE, NULL, NULL);
    if (ret >= 0) {
        fprintf(stderr, "vulnerable_dtls_hostname_connection_accepted=1\n");
        avio_closep(&io);
    } else {
        char error[AV_ERROR_MAX_STRING_SIZE];

        av_strerror(ret, error, sizeof(error));
        fprintf(stderr, "dtls_hostname_connection_rejected=%d error=%s\n",
                ret, error);
    }
    avformat_network_deinit();
    return ret < 0;
}
