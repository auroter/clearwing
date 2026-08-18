#include <stdio.h>

#include "libavutil/intreadwrite.h"
#include "libavutil/mem.h"

#ifndef RTMPPKT_SOURCE
#define RTMPPKT_SOURCE "libavformat/rtmppkt.c"
#endif

/* The repair source postdates this checkout's attributes.h spelling. */
#ifndef av_fallthrough
#define av_fallthrough ((void)0)
#endif

#include RTMPPKT_SOURCE

int main(void)
{
    const int depth = 1000000;
    const size_t size = (size_t)depth * 5 + 2;
    uint8_t *data = av_malloc(size + AV_INPUT_BUFFER_PADDING_SIZE);
    uint8_t *p = data;
    int ret;

    if (!data)
        return 2;

    for (int i = 0; i < depth; i++) {
        *p++ = AMF_DATA_TYPE_ARRAY;
        AV_WB32(p, 1);
        p += 4;
    }
    *p++ = AMF_DATA_TYPE_NULL;
    *p++ = AMF_DATA_TYPE_NULL;
    memset(p, 0, AV_INPUT_BUFFER_PADDING_SIZE);

    fprintf(stderr, "nested_strict_arrays=%d encoded_size=%zu\n", depth, size);
    fflush(stderr);
    ret = ff_amf_tag_size(data, data + size);
    fprintf(stderr, "tag_size_result=%d\n", ret);
    av_free(data);
    return ret >= 0;
}
