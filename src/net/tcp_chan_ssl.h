#pragma once

struct sockaddr;
typedef struct zl_loop_t zl_loop_t;
typedef struct nbuf_t nbuf_t;
typedef struct tcp_chan_ssl_t tcp_chan_ssl_t;
typedef struct tcp_srv_ssl_t tcp_srv_ssl_t;
typedef void (*tcp_srv_ssl_accept_cb)(tcp_srv_ssl_t *srv, tcp_chan_ssl_t *chan, void *udata);
typedef void (*tcp_chan_ssl_buffer_cb)(tcp_chan_ssl_t *chan, void *udata);
/** Triggered when TCP socket connected/eof/error
 * @param status 1 if connected, 0 if eof, -errno otherwise.
 */
typedef void (*tcp_chan_ssl_event_cb)(tcp_chan_ssl_t *chan, int status, void *udata);

int tcp_ssl_init(const char *pem, const char *key, const char *pwd);
void tcp_ssl_cleanup();

tcp_srv_ssl_t *tcp_srv_ssl_new(zl_loop_t *loop);
void tcp_srv_ssl_set_cb(tcp_srv_ssl_t *srv, tcp_srv_ssl_accept_cb accept_cb, void *udata);
int tcp_srv_ssl_bind(tcp_srv_ssl_t *srv, const char *ip, unsigned short port);
int tcp_srv_ssl_listen(tcp_srv_ssl_t *srv);
void tcp_srv_ssl_del(tcp_srv_ssl_t *srv);

tcp_chan_ssl_t *tcp_chan_ssl_connect(zl_loop_t *loop, const char *ip, unsigned port);

tcp_chan_ssl_t *tcp_chan_ssl_accept(zl_loop_t *loop, int listenfd);
void tcp_chan_ssl_set_cb(tcp_chan_ssl_t *chan, tcp_chan_ssl_buffer_cb read_cb,
                         tcp_chan_ssl_buffer_cb write_cb, tcp_chan_ssl_event_cb error_cb,
                         void *udata);
void tcp_chan_ssl_close(tcp_chan_ssl_t *chan, int flush_write);

int tcp_chan_ssl_get_read_buf_size(tcp_chan_ssl_t *chan);
int tcp_chan_ssl_read_buf_empty(tcp_chan_ssl_t * chan);
int tcp_chan_ssl_read(tcp_chan_ssl_t *chan, void *data, int size);
char tcp_chan_ssl_readc(tcp_chan_ssl_t *chan);
int tcp_chan_ssl_peek(tcp_chan_ssl_t *chan, void *data, int size);
char tcp_chan_ssl_peekc(tcp_chan_ssl_t *chan);

int tcp_chan_ssl_get_write_buf_size(tcp_chan_ssl_t *chan);
int tcp_chan_ssl_write_buf_empty(tcp_chan_ssl_t * chan);
int tcp_chan_ssl_write(tcp_chan_ssl_t *chan, const void *data, int size);
int tcp_chan_ssl_get_peername(tcp_chan_ssl_t *chan, struct sockaddr *addr, int addrlen);
int tcp_chan_ssl_fd(tcp_chan_ssl_t *chan);
