#pragma once
#include "http_types.h"
#include <stdint.h>

typedef struct rtz_server_t rtz_server_t;
typedef struct rtz_stream_t rtz_stream_t;
typedef struct zl_loop_t zl_loop_t;

rtz_server_t *rtz_server_new(zl_loop_t *loop);
zl_loop_t *rtz_server_get_loop(rtz_server_t *srv);
int rtz_server_bind(rtz_server_t *srv, unsigned short port);
void rtz_server_del(rtz_server_t *srv);
int rtz_server_start(rtz_server_t *srv);
void rtz_server_stop(rtz_server_t *srv);

void rtz_get_stream_info(rtz_server_t *srv, const char *stream_name, int *num_publisher, int *num_player);
rtz_stream_t *rtz_stream_new(rtz_server_t *srv, const char *stream_name);
void rtz_stream_del(rtz_stream_t *stream);
rtz_stream_t *rtz_stream_get(rtz_server_t *srv, const char *stream_name);
void rtz_stream_set_video_codec_h264(rtz_stream_t *session, const void *data, int size);
void rtz_stream_push_video(rtz_stream_t *stream, uint32_t rtp_timestamp,
                           int key_frame, const void *data, int size);
void rtz_stream_push_audio(rtz_stream_t *stream, uint32_t rtp_timestamp,
                           const void *data, int size);
void rtz_stream_update_videotime(rtz_stream_t *stream, double videotime);
void rtz_webrtcup(void *rtz_handle);
void rtz_hangup(void *rtz_handle);
