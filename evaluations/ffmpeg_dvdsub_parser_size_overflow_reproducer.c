#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "libavcodec/avcodec.h"
#include "libavutil/error.h"

#include "libavcodec/dvdsub_parser.c"

int main(void)
{
    AVCodecParserContext parser = {0};
    AVCodecContext codec = {0};
    DVDSubParseContext private = {0};
    uint8_t first[AV_INPUT_BUFFER_PADDING_SIZE + 2] = {0};
    const uint8_t *second;
    const uint8_t *output = NULL;
    int output_size = 0;
    int consumed;

    parser.priv_data = &private;
    codec.codec_id = AV_CODEC_ID_DVD_SUBTITLE;
    codec.codec_type = AVMEDIA_TYPE_SUBTITLE;
    first[1] = 8;
    second = mmap(NULL, INT_MAX, PROT_READ,
                  MAP_PRIVATE | MAP_ANON, -1, 0);
    if (second == MAP_FAILED) {
        fprintf(stderr, "source_mapping_failed=1\n");
        return 2;
    }

    consumed = dvdsub_parse(&parser, &codec, &output, &output_size, first, 2);
    if (consumed != 2 || output || output_size) {
        fprintf(stderr, "parser_setup_failed=1\n");
        return 2;
    }

    fprintf(stderr,
            "declared_packet_len=8 packet_index=2 second_buf_size=%d "
            "signed_sum_wraps=1\n",
            INT_MAX);
    fflush(stderr);
    dvdsub_parse(&parser, &codec, &output, &output_size, second, INT_MAX);

    fprintf(stderr, "unexpected_parser_success=1\n");
    dvdsub_parse_close(&parser);
    munmap((void *)second, INT_MAX);
    return 1;
}
