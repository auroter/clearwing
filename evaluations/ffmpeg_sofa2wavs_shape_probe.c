/*
 * Report the semantic shape that tools/sofa2wavs.c trusts after
 * mysofa_load().  The companion runner executes the unmodified FFmpeg tool
 * for the actual sanitizer fault.
 */

#include <stdio.h>

#include <mysofa.h>

static const char *attribute(struct MYSOFA_ATTRIBUTE *attributes,
                             char *name)
{
    const char *value = mysofa_getAttribute(attributes, name);
    return value ? value : "<missing>";
}

int main(int argc, char **argv)
{
    struct MYSOFA_HRTF *hrtf;
    unsigned first_unchecked_source_index;
    int check_err;
    int load_err = -1;

    if (argc != 2) {
        fprintf(stderr, "usage: %s input.sofa\n", argv[0]);
        return 2;
    }

    hrtf = mysofa_load(argv[1], &load_err);
    if (!hrtf) {
        fprintf(stderr, "load_ptr=null load_err=%d\n", load_err);
        return 1;
    }

    check_err = mysofa_check(hrtf);
    first_unchecked_source_index = hrtf->C;
    printf("load_ptr=nonnull load_err=%d check_err=%d "
           "I=%u C=%u R=%u E=%u N=%u M=%u "
           "source_elements=%u ir_elements=%u "
           "sofa_convention=%s source_dimension=%s "
           "first_unchecked_source_index=%u\n",
           load_err, check_err, hrtf->I, hrtf->C, hrtf->R, hrtf->E,
           hrtf->N, hrtf->M, hrtf->SourcePosition.elements,
           hrtf->DataIR.elements,
           attribute(hrtf->attributes, "SOFAConventions"),
           attribute(hrtf->SourcePosition.attributes, "DIMENSION_LIST"),
           first_unchecked_source_index);

    mysofa_free(hrtf);
    return 0;
}
