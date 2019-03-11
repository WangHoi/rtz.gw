#include "udp_chan.h"
#include "nbuf.h"
#include "net_util.h"
#include "event_loop.h"
#include "log.h"
#include "macro_util.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

enum {
    UDP_BUF_SIZE = 9000,
    UDP_CHAN_SND_BUF_SIZE = 655360,
    UDP_CHAN_RCV_BUF_SIZE = 655360,
};

enum {
    UDP_CHAN_IN_EVENT_CB = 1,
    UDP_CHAN_ERROR = 2,
    UDP_CHAN_CLOSING = 4,
};

struct udp_chan_t {
    zl_loop_t *loop;
    int fd;
    struct sockaddr_storage addr;
    udp_chan_buffer_cb read_cb;
    udp_chan_event_cb error_cb;
    void *udata;
    int eevents;
    int flags;
};

static void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata);
static void update_chan_events(udp_chan_t* chan);

udp_chan_t *udp_chan_new(zl_loop_t *loop)
{
    udp_chan_t *chan = malloc(sizeof(udp_chan_t));
    memset(chan, 0, sizeof(udp_chan_t));
    chan->loop = loop;
    chan->fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_socket_reuseport(chan->fd, 1);
    update_chan_events(chan);
    return chan;
}

int udp_chan_bind(udp_chan_t *chan, const char *ip, unsigned short port)
{
    struct sockaddr_in *addr = (struct sockaddr_in*)&chan->addr;
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    
    if (!ip || !strcmp(ip, "0.0.0.0"))
        addr->sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, ip, &addr->sin_addr);

    return bind(chan->fd, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
}

void udp_chan_set_cb(udp_chan_t *chan, udp_chan_buffer_cb read_cb,
                     udp_chan_event_cb error_cb, void *udata)
{
    chan->read_cb = read_cb;
    chan->error_cb = error_cb;
    chan->udata = udata;
}

void udp_chan_close(udp_chan_t *chan)
{
    udp_chan_set_cb(chan, NULL, NULL, NULL);

    /** defer close:
     *      a. in event cb
     */
    if (chan->flags & UDP_CHAN_IN_EVENT_CB) {

        chan->flags |= UDP_CHAN_CLOSING;
        return;
    }

    LLOG(LL_TRACE, "close fd %d", chan->fd);
    if (chan->eevents) {
        chan->eevents = 0;
        zl_fd_ctl(chan->loop, EPOLL_CTL_DEL, chan->fd, 0, NULL, NULL);
    }
    close(chan->fd);
    free(chan);
}

int udp_chan_write(udp_chan_t *chan, const void *data, int size,
                   const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (chan->flags & UDP_CHAN_ERROR)
        return -1;
    if (chan->flags & UDP_CHAN_CLOSING)
        return 0;
    return sendto(chan->fd, data, size, MSG_NOSIGNAL, dest_addr, addrlen);
}

int udp_chan_fd(udp_chan_t *chan)
{
    return chan->fd;
}

void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    int n, err = 0;
    char buffer[UDP_BUF_SIZE];
    struct sockaddr_storage addr;
    socklen_t addrlen;
    udp_chan_t *chan = udata;
    if (chan->flags & UDP_CHAN_ERROR)
        return;

    chan->flags |= UDP_CHAN_IN_EVENT_CB;
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
read_again:
        addrlen = sizeof(struct sockaddr_storage);
        n = recvfrom(fd, buffer, UDP_BUF_SIZE, 0, (struct sockaddr*)&addr, &addrlen);
        //LLOG(LL_TRACE, "read fd %d, ret=%d", fd, n);
        if (n == -1) {
            if (errno == EINTR)
                goto read_again;
            if (errno != EAGAIN) {
                err = -errno;
                chan->flags |= UDP_CHAN_ERROR;
                LLOG(LL_ERROR, "read fd %d error: %s.", fd, strerror(errno));
            }
        }
        if (n >= 0) {
            if (chan->read_cb)
                chan->read_cb(chan, buffer, n, (struct sockaddr*)&addr, addrlen, chan->udata);
        }
    }
    if (chan->flags & UDP_CHAN_ERROR) {
        if (chan->error_cb)
            chan->error_cb(chan, err, chan->udata);
    }

    update_chan_events(chan);
    chan->flags &= ~UDP_CHAN_IN_EVENT_CB;

    /** check deferred close */
    if (chan->flags & UDP_CHAN_CLOSING)
        udp_chan_close(chan);
}

void update_chan_events(udp_chan_t* chan)
{
    int pevents = 0;
    if (!(chan->flags & UDP_CHAN_ERROR)) {
        if (!(chan->flags & UDP_CHAN_CLOSING))
            pevents |= EPOLLIN;
    }
    if (pevents != chan->eevents) {
        int op;
        if (pevents == 0)
            op = EPOLL_CTL_DEL;
        else if (chan->eevents == 0)
            op = EPOLL_CTL_ADD;
        else
            op = EPOLL_CTL_MOD;
        chan->eevents = pevents;
        zl_fd_ctl(chan->loop, op, chan->fd, pevents, chan_fd_event_handler, chan);
    }
}
