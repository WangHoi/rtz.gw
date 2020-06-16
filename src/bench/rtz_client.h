/** @file rtz_client.h
 * Client for rtz_server benchmark.
 */
#pragma once

typedef struct zl_loop_t zl_loop_t;
typedef struct rtz_client_t rtz_client_t;

rtz_client_t *rtz_client_new(zl_loop_t *loop);
void rtz_client_del(rtz_client_t *client);

/** Connect to WebSocket signal server, create session. */
void rtz_client_open(rtz_client_t *client, const char *ip, int port);
/** Create play handle */
void rtz_client_play(rtz_client_t *client, const char *url);
/** Destroy session. */
void rtz_client_close(rtz_client_t *client);
/** Update stats. */
void rtz_update_stats(void *rtz_handle, int recv_bytes, int send_bytes);
