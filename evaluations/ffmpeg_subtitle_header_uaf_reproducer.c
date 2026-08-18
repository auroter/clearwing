#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/avcodec.h"
#include "libavutil/mem.h"

typedef struct DecoderHeaderView {
    uint8_t *subtitle_header;
    int subtitle_header_size;
} DecoderHeaderView;

static av_noinline void publish_header(DecoderHeaderView *decoder,
                                       AVCodecContext *decoder_context)
{
#ifdef REPAIRED
    decoder->subtitle_header = av_mallocz(decoder_context->subtitle_header_size + 1);
    if (!decoder->subtitle_header)
        return;
    memcpy(decoder->subtitle_header, decoder_context->subtitle_header,
           decoder_context->subtitle_header_size);
#else
    decoder->subtitle_header = decoder_context->subtitle_header;
#endif
    decoder->subtitle_header_size = decoder_context->subtitle_header_size;
}

static av_noinline unsigned consume_header(const DecoderHeaderView *decoder)
{
    uint8_t *encoder_header = av_mallocz(decoder->subtitle_header_size + 1);
    unsigned checksum = 0;

    if (!encoder_header)
        return 0;
    memcpy(encoder_header, decoder->subtitle_header,
           decoder->subtitle_header_size);
    for (int i = 0; i < decoder->subtitle_header_size; i++)
        checksum += encoder_header[i];
    av_free(encoder_header);
    return checksum;
}

int main(void)
{
    static const char header[] =
        "[Script Info]\nScriptType: v4.00+\n[V4+ Styles]\n";
    DecoderHeaderView decoder = { 0 };
    AVCodecContext *decoder_context = avcodec_alloc_context3(NULL);
    unsigned checksum;

    if (!decoder_context)
        return 2;
    decoder_context->subtitle_header_size = sizeof(header) - 1;
    decoder_context->subtitle_header =
        av_mallocz(decoder_context->subtitle_header_size + 1);
    if (!decoder_context->subtitle_header)
        return 2;
    memcpy(decoder_context->subtitle_header, header, sizeof(header) - 1);

    publish_header(&decoder, decoder_context);
    fprintf(stderr, "header_size=%d published=1\n",
            decoder.subtitle_header_size);

    avcodec_free_context(&decoder_context);
    fprintf(stderr, "decoder_context_freed=1\n");
    fflush(stderr);

    checksum = consume_header(&decoder);
    fprintf(stderr, "encoder_header_checksum=%u\n", checksum);

#ifdef REPAIRED
    av_freep(&decoder.subtitle_header);
#endif
    return checksum ? 0 : 3;
}
