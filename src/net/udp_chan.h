#pragma once
#include <sys/socket.h>

typedef struct zl_loop_t zl_loop_t;
typedef struct udp_chan_t udp_chan_t;
typedef void (*udp_chan_buffer_cb)(udp_chan_t *chan, const void *data, int size,
                                   const struct sockaddr *dest_addr, socklen_t addrlen,
                                   void *udata);
typedef void (*udp_chan_event_cb)(udp_chan_t *chan, int status, void *udata);

udp_chan_t *udp_chan_new(zl_loop_t *loop);
int udp_chan_bind(udp_chan_t *chan, const char *ip, unsigned short port);
void udp_chan_set_cb(udp_chan_t *chan, udp_chan_buffer_cb read_cb,
                     udp_chan_event_cb error_cb, void *udata);
void udp_chan_close(udp_chan_t *chan);
int udp_chan_write(udp_chan_t *chan, const void *data, int size,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
int udp_chan_fd(udp_chan_t *chan);
