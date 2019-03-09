#pragma once
#include "rtmp_types.h"
#include "list.h"
#include <stdint.h>
#include <sys/types.h>

typedef struct rtz_server_t rtz_server_t;
typedef struct zl_loop_t zl_loop_t;
typedef struct rtmp_server_t rtmp_server_t;
typedef struct rtmp_peer_t rtmp_peer_t;

rtmp_server_t *rtmp_server_new(zl_loop_t *loop, rtz_server_t *mse_srv);
int rtmp_server_bind(rtmp_server_t *srv, unsigned short port);
int rtmp_server_start(rtmp_server_t *srv);
void rtmp_server_stop(rtmp_server_t *srv);
void rtmp_server_del(rtmp_server_t *srv);
//int rtmp_peer_writeraw(struct rtmp_peer *peer, const void *buf, size_t len);
//int rtmp_peer_response(struct rtmp_peer_t *peer, struct rtmp_response_t *response);
//void rtmp_peer_update_events(struct rtmp_peer *peer);
//void rtmp_peer_close(struct rtmp_peer_t *peer);

void rtmp_stream_set_video_codec_h264(rtmp_peer_t *peer, uint32_t timestamp,
                                      const void *data, int size);
void rtmp_stream_push_video(rtmp_peer_t *peer, uint32_t timestamp,
                            int key_frame, const void *data, int size);
void rtmp_stream_push_audio(rtmp_peer_t *peer, uint32_t timestamp,
                            const void *data, int size);
void rtmp_get_player(rtmp_server_t *srv, const char *stream_name, int *player_count);
