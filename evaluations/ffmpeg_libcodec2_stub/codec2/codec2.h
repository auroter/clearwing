#ifndef PROOF_CODEC2_CODEC2_H
#define PROOF_CODEC2_CODEC2_H

#include <stdint.h>

struct CODEC2;

struct CODEC2 *codec2_create(int mode);
void codec2_destroy(struct CODEC2 *codec);
int codec2_samples_per_frame(struct CODEC2 *codec);
int codec2_bits_per_frame(struct CODEC2 *codec);
void codec2_set_natural_or_gray(struct CODEC2 *codec, int natural_or_gray);
void codec2_decode(struct CODEC2 *codec, int16_t *speech, const uint8_t *bits);
void codec2_encode(struct CODEC2 *codec, uint8_t *bits, const int16_t *speech);

#endif
