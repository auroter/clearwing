#include <stdint.h>
#include <stdio.h>

#include <sanitizer/asan_interface.h>

#include "libavutil/mem.h"
#include "libavutil/rc4.h"

int main(void)
{
    AVRC4 *context = av_rc4_alloc();
    uint8_t *zero_length_key = av_malloc(1);
    int result;

    if (!context || !zero_length_key)
        return 2;
    zero_length_key[0] = 0;
    __asan_poison_memory_region(zero_length_key, 1);
    fprintf(stderr,
            "key_bits=0 documented_multiple_of_8=1 required_key_bytes=0\n");
    fflush(stderr);
    result = av_rc4_init(context, zero_length_key, 0, 0);
    __asan_unpoison_memory_region(zero_length_key, 1);
    av_free(zero_length_key);
    av_free(context);
    fprintf(stderr, "init_result=%d\n", result);
    return result;
}
