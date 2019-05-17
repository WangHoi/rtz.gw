#pragma once

typedef struct hls_server_t hls_server_t;
typedef struct zl_loop_t zl_loop_t;

hls_server_t *hls_server_new(zl_loop_t *loop);
int hls_server_bind(hls_server_t *srv, unsigned short port);
void hls_server_del(hls_server_t *srv);
int hls_server_start(hls_server_t *srv);
void hls_server_stop(hls_server_t *srv);
