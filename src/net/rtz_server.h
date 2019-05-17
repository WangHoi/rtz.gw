#pragma once
#include "http_types.h"
#include <stdint.h>

typedef struct rtz_server_t rtz_server_t;
typedef struct rtz_stream_t rtz_stream_t;
typedef struct zl_loop_t zl_loop_t;
typedef struct rtmp_client_t rtmp_client_t;
typedef struct rtp_mux_t rtp_mux_t;
typedef struct sbuf_t sbuf_t;

/** rtz_stream_t connect publisher and subscribers together
 *
 * In Edge mode, rtz_stream_t created by first rtz_handle_t,
 *      and rtz_stream_t own the rtmp_client.
 */
struct rtz_stream_t {
    rtz_server_t *srv;
    /** link to rtz_server_t.stream_list */
    struct list_head link;

    /** Such as 'realTime_xxx_0_0' */
    sbuf_t *stream_name;

    /** Edge mode, pull rtmp stream, owned by rtz_stream_t */
    rtmp_client_t *rtmp_client;
    /** rtz_handle_t.stream_link list */
    struct list_head handle_list;

    /* last video input time */
    long long last_in_time;
    /* last video output time */
    long long last_out_time;

    rtp_mux_t *rtp_mux;
    /** Smoothed frame time, estimate FPS */
    uint16_t sframe_time;
};

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
void rtz_stream_push_video(rtz_stream_t *stream, uint32_t rtp_timestamp, uint16_t sframe_time,
                           int key_frame, const void *data, int size);
void rtz_stream_push_audio(rtz_stream_t *stream, uint32_t rtp_timestamp,
                           const void *data, int size);
void rtz_stream_update_videotime(rtz_stream_t *stream, double videotime);
void rtz_webrtcup(void *rtz_handle);
void rtz_hangup(void *rtz_handle);
void rtz_update_stats(void *rtz_handle, int recv_bytes, int sent_bytes);

int rtz_get_load(rtz_server_t *srv);

void *rtz_get_ice_server(rtz_server_t *srv);
void rtz_server_kick_stream(rtz_server_t *srv, const char *tc_url, const char *stream);

void make_origin_url(sbuf_t *origin_url, const char *tc_url, const char *stream_name);
