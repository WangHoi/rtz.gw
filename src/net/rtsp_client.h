#pragma once
#include <stdint.h>

typedef struct zl_loop_t zl_loop_t;
typedef struct rtsp_client_t rtsp_client_t;
typedef void (*zl_defer_cb)(zl_loop_t* loop, int64_t status, void *udata);
typedef void (*rtp_packet_cb)(const char *data, int size, void *udata);

rtsp_client_t *rtsp_client_new(zl_loop_t *loop);
void rtsp_client_set_userdata(rtsp_client_t *client, void *udata);
void rtsp_client_del(rtsp_client_t *client);
void rtsp_client_set_uri(rtsp_client_t *client, const char *uri);
void rtsp_client_set_user(rtsp_client_t *client, const char *user);
void rtsp_client_set_password(rtsp_client_t *client, const char *pwd);
void rtsp_client_set_packet_cb(rtsp_client_t *client, rtp_packet_cb func);
const char *rtsp_client_get_sdp(rtsp_client_t *client);
void rtsp_client_connect(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_options(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_describe(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_setup(rtsp_client_t *client, const char *control, zl_defer_cb func);
void rtsp_client_play(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_pause(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_close(rtsp_client_t *client, zl_defer_cb func);
void rtsp_client_abort(rtsp_client_t *client);
void rtsp_client_cron(zl_loop_t *loop);
