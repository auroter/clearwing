#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct SwsInternal SwsInternal;

void ff_hyscale_fast_c(SwsInternal *c, int16_t *dst, int dst_width,
                       const uint8_t *src, int src_width, int x_inc);

int main(void)
{
    const int src_width = 40000;
    const int dst_width = 40032;
    const int x_inc = 65484;
    uint8_t *src = calloc((size_t)src_width + 1, sizeof(*src));
    int16_t *dst = calloc((size_t)dst_width, sizeof(*dst));

    if (!src || !dst) {
        free(dst);
        free(src);
        return 2;
    }

    fprintf(stderr,
            "src_width=%d dst_width=%d last_i=%d x_inc=%d "
            "mathematical_product=%lld int_max=%d\n",
            src_width, dst_width, dst_width - 1, x_inc,
            (long long)(dst_width - 1) * x_inc, INT32_MAX);
    fflush(stderr);
    ff_hyscale_fast_c(NULL, dst, dst_width, src, src_width, x_inc);

    free(dst);
    free(src);
    return 0;
}
