#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "libavutil/opt.h"
#include "libavutil/version.h"

typedef struct BinaryArrayContext {
    const AVClass *class;
    uint8_t **values;
    unsigned int values_count;
} BinaryArrayContext;

static const AVOption binary_array_options[] = {
    {
        .name = "binary_array",
        .help = "binary array reproducer",
        .offset = offsetof(BinaryArrayContext, values),
        .type = AV_OPT_TYPE_BINARY | AV_OPT_TYPE_FLAG_ARRAY,
        .flags = AV_OPT_FLAG_RUNTIME_PARAM,
    },
    { NULL },
};

static const AVClass binary_array_class = {
    .class_name = "binary-array-reproducer",
    .item_name = av_default_item_name,
    .option = binary_array_options,
    .version = LIBAVUTIL_VERSION_INT,
};

int main(void)
{
    BinaryArrayContext context = { .class = &binary_array_class };

    fprintf(stderr,
            "api=av_opt_set option=binary_array element_size=%zu "
            "length_offset=%zu allocation_bytes=%zu input_hex_bytes=1\n",
            sizeof(uint8_t *), sizeof(uint8_t *), sizeof(uint8_t *));
    fflush(stderr);

    return av_opt_set(&context, "binary_array", "00", 0);
}
