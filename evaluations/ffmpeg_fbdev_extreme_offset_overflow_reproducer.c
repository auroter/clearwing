#include <limits.h>
#include <stdio.h>

#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline))
#endif
static int clip_horizontal(int video_width, unsigned int framebuffer_width,
                           int bytes_per_pixel, int xoffset)
{
    int bytes_to_copy = video_width * bytes_per_pixel;

    if (xoffset) {
        if (xoffset < 0) {
            if (-xoffset >= video_width)
                return 0;
            bytes_to_copy += xoffset * bytes_per_pixel;
        } else {
            int diff = (video_width + xoffset) - framebuffer_width;
            if (diff > 0) {
                if (diff >= video_width)
                    return 0;
                bytes_to_copy -= diff * bytes_per_pixel;
            }
        }
    }

    return bytes_to_copy;
}

int main(void)
{
    volatile int video_width = 640;
    volatile unsigned int framebuffer_width = 640;
    volatile int bytes_per_pixel = 4;
    volatile int xoffset = INT_MAX;

    fprintf(stderr,
            "video_width=%d framebuffer_width=%u bytes_per_pixel=%d "
            "xoffset=%d int_max=%d\n",
            video_width, framebuffer_width, bytes_per_pixel, xoffset, INT_MAX);
    fflush(stderr);
    return clip_horizontal(video_width, framebuffer_width,
                           bytes_per_pixel, xoffset) == 0;
}
