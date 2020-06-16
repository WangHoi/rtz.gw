#pragma once
#include <stdint.h>

typedef struct sbuf_t sbuf_t;
typedef struct fmp4_mux_t fmp4_mux_t;

/**
 * generate init segment
 * \param   has_audio
 * \param   data    video: AVCDecoderConfigurationRecord
 *                  audio: FLACSpecificBox
 */
void fmp4_mux_init_seg(sbuf_t *b, unsigned duration,
    int width, int height, const void *vcodec_data, int vcodec_size,
    int has_audio, const void *acodec_data, int acodec_size);

fmp4_mux_t *fmp4_mux_new();
void fmp4_mux_del(fmp4_mux_t *ctx);
void fmp4_mux_media_start(fmp4_mux_t *ctx);
void fmp4_mux_media_sample(fmp4_mux_t *ctx,
    int video, int64_t pts, int32_t duration,
    int key_frame, const char *data, int size);
void fmp4_mux_media_end(fmp4_mux_t *ctx,
    unsigned frag_seq, int64_t next_video_pts,
    sbuf_t *buf, double *out_duration);
double fmp4_mux_duration(fmp4_mux_t *ctx, int64_t next_video_pts);
