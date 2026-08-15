#ifndef PROOF_XAVS_H
#define PROOF_XAVS_H

#include <stdarg.h>
#include <stdint.h>

#define XAVS_LOG_ERROR 0
#define XAVS_LOG_WARNING 1
#define XAVS_LOG_INFO 2
#define XAVS_LOG_DEBUG 3
#define XAVS_CSP_I420 1
#define XAVS_TYPE_AUTO 0
#define XAVS_TYPE_IDR 1
#define XAVS_TYPE_I 2
#define XAVS_TYPE_P 3
#define XAVS_TYPE_B 4
#define XAVS_TYPE_BREF 5
#define XAVS_RC_ABR 1
#define XAVS_RC_CRF 2
#define XAVS_RC_CQP 3
#define XAVS_ANALYSE_I8x8 1
#define XAVS_ANALYSE_PSUB16x16 2
#define XAVS_ANALYSE_BSUB16x16 4
#define XAVS_DIRECT_PRED_NONE 0
#define XAVS_DIRECT_PRED_SPATIAL 1
#define XAVS_DIRECT_PRED_TEMPORAL 2
#define XAVS_DIRECT_PRED_AUTO 3
#define XAVS_ME_DIA 0
#define XAVS_ME_HEX 1
#define XAVS_ME_UMH 2
#define XAVS_ME_ESA 3
#define XAVS_ME_TESA 4
#define NAL_SEI 6

typedef struct xavs_t xavs_t;

typedef struct xavs_nal_t {
    int i_type;
    int i_payload;
} xavs_nal_t;

typedef struct xavs_picture_t {
    struct {
        int i_csp;
        int i_plane;
        uint8_t *plane[4];
        int i_stride[4];
    } img;
    int64_t i_pts;
    int i_type;
    int i_qpplus1;
} xavs_picture_t;

typedef struct xavs_param_t {
    void (*pf_log)(void *, int, const char *, va_list);
    void *p_log_private;
    int i_keyint_max;
    struct {
        int i_bitrate;
        int i_rc_method;
        int i_vbv_buffer_size;
        int i_vbv_max_bitrate;
        int b_stat_write;
        int b_stat_read;
        float f_rf_constant;
        float f_complexity_blur;
        int i_qp_constant;
        int b_mb_tree;
        int i_qp_min;
        int i_qp_max;
        int i_qp_step;
        float f_qcompress;
        float f_qblur;
        float f_rate_tolerance;
        float f_vbv_buffer_init;
        float f_ip_factor;
        float f_pb_factor;
    } rc;
    int b_aud;
    struct {
        int i_direct_mv_pred;
        int b_fast_pskip;
        int i_me_method;
        int b_mixed_references;
        int inter;
        int i_me_range;
        int i_subpel_refine;
        int b_chroma_me;
        int b_transform_8x8;
        int i_trellis;
        int i_noise_reduction;
        int i_chroma_qp_offset;
        int b_psnr;
    } analyse;
    int i_bframe_bias;
    int i_bframe;
    int b_cabac;
    int i_bframe_adaptive;
    int i_keyint_min;
    int i_scenecut_threshold;
    int i_frame_reference;
    int i_width;
    int i_height;
    struct {
        int i_sar_width;
        int i_sar_height;
    } vui;
    int i_fps_num;
    int i_fps_den;
    int i_level_idc;
    int i_log_level;
    int i_threads;
    int b_interlaced;
    int b_repeat_headers;
} xavs_param_t;

void xavs_param_default(xavs_param_t *params);
xavs_t *xavs_encoder_open(xavs_param_t *params);
void xavs_encoder_close(xavs_t *encoder);
int xavs_encoder_encode(xavs_t *encoder, xavs_nal_t **nals, int *nnal,
                        xavs_picture_t *input, xavs_picture_t *output);
int xavs_encoder_headers(xavs_t *encoder, xavs_nal_t **nals, int *nnal);
int xavs_nal_encode(uint8_t *destination, int *size, int annexb,
                    xavs_nal_t *nal);

#endif
