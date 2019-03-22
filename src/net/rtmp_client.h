#pragma once
#include <stdint.h>

typedef enum rtmp_status_t {
    RTMP_SKIP_RESPONSE = 300,
    RTMP_INVALID_STATUS = 301,

    RTMP_NETSTREAM_BUFFER_EMPTY = 310,
    RTMP_NETSTREAM_BUFFER_FULL,
    RTMP_NETSTREAM_BUFFER_FLUSH,

    RTMP_NETSTREAM_PUBLISH_START = 320,
    RTMP_NETSTREAM_PUBLISH_BADNAME,
    RTMP_NETSTREAM_PUBLISH_IDLE,
    RTMP_NETSTREAM_UNPUBLISH_SUCCESS,

    RTMP_NETSTREAM_PLAY_START = 340,
    RTMP_NETSTREAM_PLAY_STOP,
    RTMP_NETSTREAM_PLAY_FAILED,
    RTMP_NETSTREAM_PLAY_STREAM_NOT_FOUND,
    RTMP_NETSTREAM_PLAY_RESET,
    RTMP_NETSTREAM_PLAY_PUBLISH_NOTIFY,
    RTMP_NETSTREAM_PLAY_UNPUBLISH_NOTIFY,
    RTMP_NETSTREAM_PAUSE_NOTIFY,
    RTMP_NETSTREAM_UNPAUSE_NOTIFY,

    RTMP_NETCONNECTION_CLOSED = 360,
    RTMP_NETCONNECTION_FAILED,
    RTMP_NETCONNECTION_SUCCESS,
    RTMP_NETCONNECTION_REJECTED,
    RTMP_NETCONNECTION_APP_SHUTDOWN,
    RTMP_NETCONNECTION_INVALID_APP,
} rtmp_status_t;

typedef struct zl_loop_t zl_loop_t;
typedef struct rtmp_client_t rtmp_client_t;
typedef void (*zl_defer_cb)(zl_loop_t* loop, int64_t status, void *udata);
typedef void (*rtmp_packet_cb)(int64_t timestamp, const char *data, int size, void *udata);

rtmp_client_t *rtmp_client_new(zl_loop_t *loop);
//void rtmp_client_set_userdata(rtmp_client_t *client, void *udata);
void rtmp_client_del(rtmp_client_t *client);
void rtmp_client_set_uri(rtmp_client_t *client, const char *uri);
//void rtmp_client_set_packet_cb(rtmp_client_t *client, rtp_packet_cb func);
//const char *rtmp_client_get_sdp(rtmp_client_t *client);
void rtmp_client_tcp_connect(rtmp_client_t *client, zl_defer_cb func);
/*
void rtmp_client_connect(rtmp_client_t *client, zl_defer_cb func);
void rtmp_client_create_stream(rtmp_client_t *client, zl_defer_cb func);
void rtmp_client_play(rtmp_client_t *client, zl_defer_cb func);
void rtmp_client_release_stream(rtmp_client_t *client, zl_defer_cb func);
void rtmp_client_fcpublish(rtmp_client_t *client, zl_defer_cb func);
void rtmp_client_publish(rtmp_client_t *client, zl_defer_cb func);
*/
void rtmp_client_abort(rtmp_client_t *client);
void rtmp_client_set_rtz_stream(rtmp_client_t *client, void *rtz_stream);
/*
void rtmp_client_set_video_packet_cb(rtmp_client_t *client, rtmp_packet_cb func);
void rtmp_client_set_audio_packet_cb(rtmp_client_t *client, rtmp_packet_cb func);
void rtmp_client_send_video(rtmp_client_t *client, uint32_t timestamp,
                            const char *data, int size);
*/
