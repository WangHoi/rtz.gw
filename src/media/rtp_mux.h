#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct rtp_mux_t rtp_mux_t;

typedef void (*rtp_mux_cb)(int video, int kf, void *data, int size, void *udata);

rtp_mux_t *rtp_mux_new();
void rtp_mux_reset(rtp_mux_t *ctx);
void rtp_mux_set_cb(rtp_mux_t *ctx, rtp_mux_cb func, void *udata);
void rtp_mux_del(rtp_mux_t *ctx);
void rtp_mux_input(rtp_mux_t *ctx, int video, uint32_t timestamp,
                   const void *data, int size);
void rtp_mux_set_sps_pps(rtp_mux_t *ctx, const void *sps_data, int sps_size,
                         const void *pps_data, int pps_size);
