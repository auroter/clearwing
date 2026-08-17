#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/bsf.h"
#include "libavcodec/packet.h"
#include "libavutil/dovi_meta.h"
#include "libavutil/log.h"

int main(void)
{
    static const uint8_t av1_packet[] = {
        0x2a, 0x36, 0x04, 0xb5, 0x00, 0x3b, 0x00, 0x00,
        0x08, 0x00, 0x37, 0xcd, 0x08, 0x20, 0xc0, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x07,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80,
    };
    const AVBitStreamFilter *filter = av_bsf_get_by_name("dovi_rpu");
    AVBSFContext *bsf = NULL;
    AVPacketSideData *side_data;
    AVDOVIDecoderConfigurationRecord *cfg;
    AVPacket *packet = NULL;
    AVPacket *output = NULL;
    int ret;

    av_log_set_level(AV_LOG_WARNING);
    if (!filter) {
        fprintf(stderr, "dovi_rpu bitstream filter is unavailable\n");
        return 2;
    }

    ret = av_bsf_alloc(filter, &bsf);
    if (ret < 0)
        return 2;
    bsf->par_in->codec_type = AVMEDIA_TYPE_VIDEO;
    bsf->par_in->codec_id = AV_CODEC_ID_AV1;

    side_data = av_packet_side_data_new(&bsf->par_in->coded_side_data,
                                        &bsf->par_in->nb_coded_side_data,
                                        AV_PKT_DATA_DOVI_CONF,
                                        sizeof(*cfg), 0);
    if (!side_data)
        return 2;
    cfg = (AVDOVIDecoderConfigurationRecord *)side_data->data;
    cfg->dv_version_major = 1;
    cfg->dv_profile = 10;
    cfg->rpu_present_flag = 1;

    ret = av_bsf_init(bsf);
    printf("entry=av_bsf_init codec=av1 ret=%d\n", ret);
    fflush(stdout);
    if (ret < 0)
        return 2;

    packet = av_packet_alloc();
    output = av_packet_alloc();
    if (!packet || !output || av_new_packet(packet, sizeof(av1_packet)) < 0)
        return 2;
    memcpy(packet->data, av1_packet, sizeof(av1_packet));

    printf("packet_size=%zu rpu_type=0 metadata_expected=absent\n",
           sizeof(av1_packet));
    fflush(stdout);
    ret = av_bsf_send_packet(bsf, packet);
    printf("send_ret=%d entering=av_bsf_receive_packet\n", ret);
    fflush(stdout);
    if (ret < 0)
        return 2;

    ret = av_bsf_receive_packet(bsf, output);
    printf("receive_ret=%d output_size=%d\n", ret, output->size);
    fflush(stdout);

    av_packet_free(&packet);
    av_packet_free(&output);
    av_bsf_free(&bsf);
    return ret < 0;
}
