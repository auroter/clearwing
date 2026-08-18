#ifndef CLEARWING_CHROMAPRINT_STUB_H
#define CLEARWING_CHROMAPRINT_STUB_H

#include <stdint.h>

#define CHROMAPRINT_VERSION_MAJOR 1
#define CHROMAPRINT_VERSION_MINOR 4
#define CHROMAPRINT_VERSION_PATCH 0

#define CHROMAPRINT_ALGORITHM_TEST1 0
#define CHROMAPRINT_ALGORITHM_DEFAULT 1

typedef struct ChromaprintContext ChromaprintContext;

ChromaprintContext *chromaprint_new(int algorithm);
void chromaprint_free(ChromaprintContext *ctx);
int chromaprint_set_option(ChromaprintContext *ctx, const char *name, int value);
int chromaprint_start(ChromaprintContext *ctx, int sample_rate, int channels);
int chromaprint_feed(ChromaprintContext *ctx, const int16_t *data, int size);
int chromaprint_finish(ChromaprintContext *ctx);
int chromaprint_get_raw_fingerprint(ChromaprintContext *ctx,
                                    uint32_t **fingerprint, int *size);
int chromaprint_encode_fingerprint(const uint32_t *fingerprint, int size,
                                   int algorithm, char **encoded,
                                   int *encoded_size, int base64);
void chromaprint_dealloc(void *pointer);

#endif
