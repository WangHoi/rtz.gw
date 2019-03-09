#pragma once
#include "http_types.h"
#include <stdint.h>

typedef struct mse_server_t mse_server_t;
typedef struct mse_session_t mse_session_t;
typedef struct zl_loop_t zl_loop_t;

mse_server_t *mse_server_new(zl_loop_t *loop);
zl_loop_t *mse_server_get_loop(mse_server_t *srv);
int mse_server_bind(mse_server_t *srv, unsigned short port);
void mse_server_del(mse_server_t *srv);
int mse_server_start(mse_server_t *srv);
void mse_server_stop(mse_server_t *srv);

mse_session_t *mse_session_new(mse_server_t *srv, const char *path);
void mse_session_del(mse_session_t *session);
void mse_session_set_video_codec_h264(mse_session_t *session, const char *data, int size);
void mse_session_push_video(mse_session_t *session, int64_t timestamp, int32_t duration,
                            int key_frame, const char *data, int size);
void mse_session_set_audio_codec_flac(mse_session_t *session, const char *data, int size);
void mse_session_push_audio(mse_session_t *session, int64_t timestamp, int32_t duration,
                            int key_frame, const char *data, int size);
