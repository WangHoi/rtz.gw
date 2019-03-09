#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct ps_rtp_demux_t ps_rtp_demux_t;
typedef struct nalu_part_t nalu_part_t;
typedef void (*ps_rtp_demux_video_cb)(int64_t pts, int64_t ntp_ts,
                                      const nalu_part_t *units, size_t num_units,
                                      void *udata);
typedef void (*ps_rtp_demux_audio_cb)(int64_t pts, int64_t ntp_ts,
                                      const char *data, size_t size, void *udata);

ps_rtp_demux_t *ps_rtp_demux_new();
void ps_rtp_demux_reset(ps_rtp_demux_t *ctx);
void ps_rtp_demux_set_userdata(ps_rtp_demux_t *ctx, void *udata);
void ps_rtp_demux_set_video_cb(ps_rtp_demux_t *ctx, ps_rtp_demux_video_cb func);
void ps_rtp_demux_set_audio_cb(ps_rtp_demux_t *ctx, ps_rtp_demux_audio_cb func);
void ps_rtp_demux_del(ps_rtp_demux_t *ctx);
void ps_rtp_demux_input(ps_rtp_demux_t *ctx, const void *data, size_t size);
