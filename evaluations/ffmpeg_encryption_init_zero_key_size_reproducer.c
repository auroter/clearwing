#include <stdint.h>
#include <stdio.h>

#include "libavutil/encryption_info.h"

int main(void)
{
    static const uint8_t side_data[20] = {
        0x00, 0x00, 0x00, 0x01, /* init_info_count */
        0x00, 0x00, 0x00, 0x00, /* system_id_size */
        0x00, 0x00, 0x00, 0x01, /* num_key_ids */
        0x00, 0x00, 0x00, 0x00, /* key_id_size */
        0x00, 0x00, 0x00, 0x00, /* data_size */
    };
    AVEncryptionInitInfo *info;

    fprintf(stderr,
            "api=av_encryption_init_info_get_side_data side_data_size=20 "
            "init_info_count=1 num_key_ids=1 key_id_size=0\n");
    fflush(stderr);
    info = av_encryption_init_info_get_side_data(side_data, sizeof(side_data));
    fprintf(stderr, "unexpected_parse_result=%p\n", (void *)info);
    av_encryption_init_info_free(info);
    return info == NULL;
}
