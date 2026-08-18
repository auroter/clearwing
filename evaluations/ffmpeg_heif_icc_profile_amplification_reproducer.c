#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef MOV_SOURCE
#define MOV_SOURCE "libavformat/mov.c"
#endif
#include MOV_SOURCE

/* The configured proof build deliberately disables the MOV demuxer, so its
 * archive omits helpers referenced by unrelated entries in mov.c's global
 * parse table. These link-only definitions are never reached by the iprp/colr
 * path under test. */
const uint16_t ff_ac3_channel_layout_tab[8];
const AVCodecTag ff_codec_movdata_tags[] = { { AV_CODEC_ID_NONE, 0 } };
const AVCodecTag ff_codec_movsubtitle_tags[] = { { AV_CODEC_ID_NONE, 0 } };
const struct MP4TrackKindMapping ff_mov_track_kind_table[] = { { NULL, NULL } };

int ff_get_qtpalette(int codec_id, AVIOContext *pb, uint32_t *palette)
{
    return 0;
}

int ff_get_wav_header(AVFormatContext *s, AVIOContext *pb,
                      AVCodecParameters *par, int size, int big_endian)
{
    return 0;
}

int ff_isom_parse_dvcc_dvvc(void *logctx, AVStream *st,
                            const uint8_t *buf_ptr, uint64_t size)
{
    return 0;
}

int ff_mov_lang_to_iso639(unsigned code, char to[4])
{
    return 0;
}

int ff_mov_read_chan(AVFormatContext *s, AVIOContext *pb, AVStream *st,
                     int64_t size)
{
    return 0;
}

int ff_mov_read_chnl(AVFormatContext *s, AVIOContext *pb, AVStream *st)
{
    return 0;
}

int ff_mov_read_esds(AVFormatContext *fc, AVIOContext *pb)
{
    return 0;
}

static void write_be16(uint8_t **cursor, unsigned value)
{
    AV_WB16(*cursor, value);
    *cursor += 2;
}

static void write_be32(uint8_t **cursor, uint32_t value)
{
    AV_WB32(*cursor, value);
    *cursor += 4;
}

static void write_tag(uint8_t **cursor, const char tag[4])
{
    memcpy(*cursor, tag, 4);
    *cursor += 4;
}

int main(void)
{
    const int item_count = 32;
    const int max_streams = 8;
    const size_t profile_size = 1U << 20;
    const size_t property_size = profile_size + 4;
    const size_t colr_size = property_size + 8;
    const size_t ipco_size = colr_size + 8;
    const size_t ipma_size = 16 + 4 * item_count;
    const size_t iprp_payload_size = ipco_size + ipma_size;
    AVFormatContext format_context = { 0 };
    MOVContext mov_context = { 0 };
    FFIOContext iprp_reader;
    uint8_t *iprp_payload = NULL;
    uint8_t *cursor;
    size_t copied_bytes = 0;
    int copied_items = 0;
    int ret = 0;

    iprp_payload = av_mallocz(iprp_payload_size);
    mov_context.heif_item = av_calloc(item_count,
                                      sizeof(*mov_context.heif_item));
    if (!iprp_payload || !mov_context.heif_item)
        return 2;

    cursor = iprp_payload;
    write_be32(&cursor, ipco_size);
    write_tag(&cursor, "ipco");
    write_be32(&cursor, colr_size);
    write_tag(&cursor, "colr");
    write_tag(&cursor, "prof");
    memset(cursor, 0x49, profile_size);
    cursor += profile_size;
    write_be32(&cursor, ipma_size);
    write_tag(&cursor, "ipma");
    write_be32(&cursor, 0); /* version and flags */
    write_be32(&cursor, item_count);
    for (int i = 0; i < item_count; i++) {
        write_be16(&cursor, i + 1);
        *cursor++ = 1; /* association count */
        *cursor++ = 1; /* first ipco property */
    }
    if (cursor != iprp_payload + iprp_payload_size)
        return 3;

    format_context.max_streams = max_streams;
    mov_context.fc = &format_context;
    mov_context.cur_item_id = -1;
    mov_context.nb_heif_item = item_count;

    for (int i = 0; i < item_count; i++) {
        HEIFItem *item = av_mallocz(sizeof(*item));

        if (!item) {
            ret = AVERROR(ENOMEM);
            break;
        }
        item->item_id = i + 1;
        mov_context.heif_item[i] = item;
    }

    ffio_init_read_context(&iprp_reader, iprp_payload, iprp_payload_size);
    ret = mov_read_iprp(&mov_context, &iprp_reader.pub,
                        (MOVAtom) { .size = iprp_payload_size,
                                    .type = MKTAG('i', 'p', 'r', 'p') });

    for (int i = 0; i < item_count; i++) {
        HEIFItem *item = mov_context.heif_item[i];

        if (!item)
            continue;
        if (item->icc_profile) {
            copied_items++;
            copied_bytes += item->icc_profile_size;
        }
    }

    fprintf(stderr,
            "shared_profile_bytes=%zu ipma_item_associations=%d "
            "max_streams=%d copied_items=%d copied_bytes=%zu result=%d\n",
            profile_size, item_count, max_streams, copied_items,
            copied_bytes, ret);

    for (int i = 0; i < item_count; i++) {
        HEIFItem *item = mov_context.heif_item[i];

        if (!item)
            continue;
        av_freep(&item->icc_profile);
        av_free(item);
    }
    av_free(mov_context.heif_item);
    av_free(iprp_payload);

    return ret < 0;
}
