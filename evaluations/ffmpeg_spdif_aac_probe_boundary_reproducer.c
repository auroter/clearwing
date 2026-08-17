#include <stdint.h>
#include <stdio.h>

#include "libavcodec/adts_parser.h"
#include "libavcodec/codec_id.h"

int ff_spdif_probe(const uint8_t *p_buf, int buf_size, enum AVCodecID *codec);

int main(void)
{
    static const uint8_t input[] = {
        0x72, 0xF8, 0x1F, 0x4E, /* IEC 61937 sync words */
        0x07, 0x00, 0x00, 0x00, /* MPEG-2 AAC and burst length */
        0xFF, 0xF1, 0x50, 0x80, 0x00, 0xFF, /* first six ADTS bytes */
        0xFC,                         /* seventh byte, outside logical size */
    };
    enum AVCodecID codec = AV_CODEC_ID_NONE;
    uint32_t samples = 0;
    uint8_t frames = 0;
    int adts = av_adts_header_parse(&input[8], &samples, &frames);
    int score = ff_spdif_probe(input, 14, &codec);

    printf("logical=14 allocated=%zu tail=%02x adts=%d samples=%u "
           "frames=%u score=%d codec=%d\n",
           sizeof(input), input[14], adts, samples, frames, score, codec);
    return 0;
}
