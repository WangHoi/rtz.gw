#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct sdp_t sdp_t;
typedef struct rtp_demux_t rtp_demux_t;
typedef struct nalu_part_t nalu_part_t;

typedef void (*rtp_demux_video_cb)(int64_t pts, int64_t ntp_ts, int64_t duration,
                                   const nalu_part_t *units, size_t num_units,
                                   void *udata);
typedef void (*rtp_demux_audio_cb)(int64_t pts, int64_t ntp_ts, int64_t duration,
                                   const char *data, size_t size,
                                   void *udata);

rtp_demux_t *rtp_demux_new();
void rtp_demux_reset(rtp_demux_t *ctx);
void rtp_demux_set_userdata(rtp_demux_t *ctx, void *udata);
void rtp_demux_set_video_cb(rtp_demux_t *ctx, rtp_demux_video_cb func);
void rtp_demux_set_audio_cb(rtp_demux_t *ctx, rtp_demux_audio_cb func);
void rtp_demux_del(rtp_demux_t *ctx);
void rtp_demux_input(rtp_demux_t *ctx, const void *data, size_t size);
void rtp_demux_sdp(rtp_demux_t *ctx, sdp_t *sdp);
