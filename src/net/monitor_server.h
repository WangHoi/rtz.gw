#pragma once
#include "http_types.h"
#include <stdint.h>

typedef struct monitor_server_t monitor_server_t;
typedef struct rtz_server_t rtz_server_t;
typedef struct rtmp_server_t rtmp_server_t;
typedef struct zl_loop_t zl_loop_t;

monitor_server_t *monitor_server_new(zl_loop_t *loop,
                                     rtz_server_t *rtz_srv,
                                     rtmp_server_t *rtmp_srv);
zl_loop_t *monitor_server_get_loop(monitor_server_t *srv);
int monitor_server_bind(monitor_server_t *srv, unsigned short port);
void monitor_server_del(monitor_server_t *srv);
int monitor_server_start(monitor_server_t *srv);
void monitor_server_stop(monitor_server_t *srv);
