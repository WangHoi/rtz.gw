#pragma once

struct iovec;
struct sockaddr;
typedef struct zl_loop_t zl_loop_t;
typedef struct nbuf_t nbuf_t;
typedef struct tcp_chan_t tcp_chan_t;
typedef struct tcp_srv_t tcp_srv_t;
typedef void (*tcp_srv_accept_cb)(tcp_srv_t *srv, tcp_chan_t *chan, void *udata);
typedef void (*tcp_chan_buffer_cb)(tcp_chan_t *chan, void *udata);
/** Triggered when TCP socket connected/eof/error
 * @param status 1 if connected, 0 if eof, -errno otherwise.
 */
typedef void (*tcp_chan_event_cb)(tcp_chan_t *chan, int status, void *udata);

tcp_srv_t *tcp_srv_new(zl_loop_t *loop);
void tcp_srv_set_cb(tcp_srv_t *srv, tcp_srv_accept_cb accept_cb, void *udata);
int tcp_srv_bind(tcp_srv_t *srv, const char *ip, unsigned short port);
int tcp_srv_listen(tcp_srv_t *srv);
void tcp_srv_del(tcp_srv_t *srv);

tcp_chan_t *tcp_connect(zl_loop_t *loop, const char *ip, unsigned port);

tcp_chan_t *tcp_chan_accept(zl_loop_t *loop, int listenfd);
void tcp_chan_set_cb(tcp_chan_t *chan, tcp_chan_buffer_cb read_cb,
                     tcp_chan_buffer_cb write_cb, tcp_chan_event_cb error_cb,
                     void *udata);
void tcp_chan_close(tcp_chan_t *chan, int flush_write);

int tcp_chan_get_read_buf_size(tcp_chan_t *chan);
int tcp_chan_read_buf_empty(tcp_chan_t * chan);
int tcp_chan_read(tcp_chan_t *chan, void *data, int size);
char tcp_chan_readc(tcp_chan_t *chan);
int tcp_chan_peek(tcp_chan_t *chan, void *data, int size);
char tcp_chan_peekc(tcp_chan_t *chan);

void tcp_chan_enable_poll_writable(tcp_chan_t *chan, int enable);
int tcp_chan_write(tcp_chan_t *chan, const void *data, int size);
int tcp_chan_writev(tcp_chan_t *chan, struct iovec *iov, int iov_cnt);
int tcp_chan_get_peername(tcp_chan_t *chan, struct sockaddr *addr, int addrlen);
int tcp_chan_fd(tcp_chan_t *chan);

void tcp_chan_set_userdata(tcp_chan_t *chan, void *udata);
void *tcp_chan_get_userdata(tcp_chan_t *chan);

void tcp_chan_detach(tcp_chan_t *chan);
/** Attach tcp_chan to another thread loop.
 *
 * @note Will re-trigger event cb.
 */
void tcp_chan_attach(tcp_chan_t *chan, zl_loop_t *loop);
void tcp_chan_set_usertag(tcp_chan_t *chan, int tag);
int tcp_chan_get_usertag(tcp_chan_t *chan);
