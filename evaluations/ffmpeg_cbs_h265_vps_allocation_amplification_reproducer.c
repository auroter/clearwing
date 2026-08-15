#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "libavcodec/cbs.h"
#include "libavcodec/cbs_h265.h"
#include "libavcodec/hevc/hevc.h"

#define PROOF_UNITS 16

int main(void)
{
    static const uint8_t vps[] = {
        0x00, 0x00, 0x00, 0x01, 0x40, 0x01, 0x0c, 0x01,
        0xff, 0xff, 0x01, 0x60, 0x00, 0x00, 0x03, 0x00,
        0xb0, 0x00, 0x00, 0x03, 0x00, 0x00, 0x03, 0x00,
        0x5d, 0xac, 0x59,
    };
    CodedBitstreamContext *ctx = NULL;
    CodedBitstreamFragment fragment = { 0 };
    uint8_t packet[sizeof(vps) * PROOF_UNITS];
    uint64_t projected;
    int content_units = 0;
    int err;

    err = ff_cbs_init(&ctx, AV_CODEC_ID_HEVC, NULL);
    if (err < 0)
        return 2;

    for (int i = 0; i < PROOF_UNITS; i++)
        memcpy(packet + i * sizeof(vps), vps, sizeof(vps));

    err = ff_cbs_read(ctx, &fragment, NULL, packet, sizeof(packet));
    if (err < 0)
        return 4;
    for (int i = 0; i < fragment.nb_units; i++)
        content_units += fragment.units[i].content != NULL;

    projected = (uint64_t)sizeof(H265RawVPS) * HEVC_MAX_LAYER_SETS;
    printf("vps_content_size=%zu hrd_parameter_size=%zu "
           "layer_sets=%d packet_bytes=%zu parsed_units=%d "
           "content_units=%d allocated_content_bytes=%zu "
           "projected_1024_packet_bytes=%zu "
           "projected_1024_content_bytes=%" PRIu64 "\n",
           sizeof(H265RawVPS), sizeof(H265RawHRDParameters),
           HEVC_MAX_LAYER_SETS, sizeof(packet), fragment.nb_units,
           content_units, sizeof(H265RawVPS) * (size_t)content_units,
           sizeof(vps) * (size_t)HEVC_MAX_LAYER_SETS, projected);

    ff_cbs_fragment_free(&fragment);
    ff_cbs_close(&ctx);
    return content_units == PROOF_UNITS ? 0 : 5;
}
