#include <limits.h>
#include <stdio.h>

#if defined(__clang__) || defined(__GNUC__)
__attribute__((noinline))
#endif
static int calculate_canvas_width(int captured_width, int crop_left,
                                  int crop_right, int canvas_width)
{
    int cap_w = captured_width - crop_left - crop_right;

    fprintf(stderr,
            "captured_width=%d crop_left=%d crop_right=%d "
            "cap_w=%d canvas_width=%d capture_border=1\n",
            captured_width, crop_left, crop_right, cap_w, canvas_width);
    fflush(stderr);

    if (canvas_width == 0)
        canvas_width = cap_w;
    else if (canvas_width < 0)
        canvas_width = (cap_w / canvas_width) * canvas_width;

    return canvas_width;
}

int main(void)
{
    volatile int captured_width = 1920;
    volatile int crop_left = 1921;
    volatile int crop_right = INT_MAX;
    volatile int canvas_width = -1;

    return calculate_canvas_width(captured_width, crop_left, crop_right,
                                  canvas_width) == 0;
}
