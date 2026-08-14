#include <stdio.h>
#include <string.h>

#include "libavcodec/hw_base_encode.c"

int main(void)
{
    AVCodecContext avctx;
    FFHWBaseEncodeContext ctx;

    memset(&avctx, 0, sizeof(avctx));
    memset(&ctx, 0, sizeof(ctx));

    fprintf(stderr,
            "empty_flush_state=1 input_order=%d decode_delay=%d "
            "pic_start_null=%d pic_end_null=%d\n",
            ctx.input_order, ctx.decode_delay,
            ctx.pic_start == NULL, ctx.pic_end == NULL);

    return hw_base_encode_send_frame(&avctx, &ctx, NULL);
}
