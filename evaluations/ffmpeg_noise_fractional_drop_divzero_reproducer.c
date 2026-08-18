#include <stdint.h>
#include <stdio.h>

#include "libavcodec/bsf.h"
#include "libavcodec/packet.h"
#include "libavutil/error.h"
#include "libavutil/opt.h"

int main(void)
{
    const AVBitStreamFilter *filter = av_bsf_get_by_name("noise");
    AVBSFContext *bsf = NULL;
    AVPacket *input = NULL;
    AVPacket *output = NULL;
    int ret = 2;

    if (!filter || av_bsf_alloc(filter, &bsf) < 0)
        goto done;
    bsf->par_in->codec_type = AVMEDIA_TYPE_VIDEO;
    bsf->par_in->codec_id = AV_CODEC_ID_MPEG2VIDEO;
    bsf->time_base_in = (AVRational){1, 25};
    if (av_opt_set(bsf->priv_data, "drop", "-0.5", 0) < 0 ||
        av_bsf_init(bsf) < 0)
        goto done;

    input = av_packet_alloc();
    output = av_packet_alloc();
    if (!input || !output || av_new_packet(input, 1) < 0)
        goto done;
    input->data[0] = 0;
    fprintf(stderr,
            "bsf=noise drop_expression=-0.5 evaluated=-0.5 "
            "integer_period=0 packet_size=1\n");
    fflush(stderr);
    if (av_bsf_send_packet(bsf, input) < 0)
        goto done;
    ret = av_bsf_receive_packet(bsf, output);
    fprintf(stderr, "unexpected_receive_return=%d\n", ret);
    ret = ret < 0;

done:
    av_packet_free(&input);
    av_packet_free(&output);
    av_bsf_free(&bsf);
    return ret;
}
