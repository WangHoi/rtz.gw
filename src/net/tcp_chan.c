#include "tcp_chan.h"
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
    TCP_CHAN_SND_BUF_SIZE = 65536,
    TCP_CHAN_RCV_BUF_SIZE = 65536,
};

enum {
    TCP_CHAN_IN_EVENT_CB = 1,
    TCP_CHAN_ERROR = 2,
    TCP_CHAN_CLOSING = 4,
    TCP_CHAN_CONNECTING = 8,
};

struct tcp_srv_t {
    zl_loop_t *loop;
    int fd;
    struct sockaddr_storage addr;
    tcp_srv_accept_cb accept_cb;
    void *udata;
    int flags;
};

struct tcp_chan_t {
    zl_loop_t *loop;
    int fd;
    struct sockaddr_storage addr;
    nbuf_t *rcv_buf;
    nbuf_t *snd_buf;
    tcp_chan_buffer_cb read_cb;
    tcp_chan_buffer_cb write_cb;
    tcp_chan_event_cb error_cb;
    void *udata;
    int eevents;
    int flags;
};

static void srv_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata);
static void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata);
static void update_chan_events(tcp_chan_t* chan);

tcp_srv_t *tcp_srv_new(zl_loop_t *loop)
{
    tcp_srv_t *srv = malloc(sizeof(tcp_srv_t));
    memset(srv, 0, sizeof(tcp_srv_t));
    srv->loop = loop;
    srv->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_socket_reuseport(srv->fd, 1);
    return srv;
}
void tcp_srv_set_cb(tcp_srv_t *srv, tcp_srv_accept_cb accept_cb, void *udata)
{
    srv->accept_cb = accept_cb;
    srv->udata = udata;
}
int tcp_srv_bind(tcp_srv_t *srv, const char *ip, unsigned short port)
{
    struct sockaddr_in *addr = (struct sockaddr_in*)&srv->addr;
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    
    if (!ip || !strcmp(ip, "0.0.0.0"))
        addr->sin_addr.s_addr = INADDR_ANY;
    else
        inet_pton(AF_INET, ip, &addr->sin_addr);

    return bind(srv->fd, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
}

int tcp_srv_listen(tcp_srv_t *srv)
{
    zl_fd_ctl(srv->loop, EPOLL_CTL_ADD, srv->fd, EPOLLIN, srv_fd_event_handler, srv);
    return listen(srv->fd, 511);
}

void tcp_srv_del(tcp_srv_t *srv)
{
    zl_fd_ctl(srv->loop, EPOLL_CTL_DEL, srv->fd, 0, NULL, NULL);
    close(srv->fd);
    free(srv);
}

tcp_chan_t *tcp_chan_accept(zl_loop_t *loop, int listenfd)
{
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    tcp_chan_t *chan = malloc(sizeof(tcp_chan_t));
    memset(chan, 0, sizeof(tcp_chan_t));
    chan->loop = loop;
again:
    chan->fd = accept4(listenfd, (struct sockaddr*)&chan->addr, &addr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (chan->fd == -1) {
        if (errno == EINTR)
            goto again;
        goto err_out;
    }
    //LLOG(LL_TRACE, "new fd %d", chan->fd);
    set_tcp_nodelay(chan->fd, 1);
    chan->rcv_buf = nbuf_new1(TCP_CHAN_RCV_BUF_SIZE);
    chan->snd_buf = nbuf_new1(TCP_CHAN_SND_BUF_SIZE);
    update_chan_events(chan);
    return chan;

err_out:
    free(chan);
    return NULL;
}

void tcp_chan_set_cb(tcp_chan_t *chan, tcp_chan_buffer_cb read_cb,
                     tcp_chan_buffer_cb write_cb, tcp_chan_event_cb error_cb,
                     void *udata)
{
    chan->read_cb = read_cb;
    chan->write_cb = write_cb;
    chan->error_cb = error_cb;
    chan->udata = udata;
}

void tcp_chan_close(tcp_chan_t *chan, int flush_write)
{
    tcp_chan_set_cb(chan, NULL, NULL, NULL, NULL);

    /** defer close:
     *      a. in event cb
     *      b. pending buffer to send
     */
    if ((chan->flags & TCP_CHAN_IN_EVENT_CB)
        || (flush_write && !(chan->flags & TCP_CHAN_ERROR) && !nbuf_empty(chan->snd_buf))) {

        chan->flags |= TCP_CHAN_CLOSING;
        return;
    }

    //LLOG(LL_TRACE, "close fd %d", chan->fd);
    if (chan->eevents) {
        chan->eevents = 0;
        if (chan->loop)
            zl_fd_ctl(chan->loop, EPOLL_CTL_DEL, chan->fd, 0, NULL, NULL);
    }
    nbuf_del(chan->rcv_buf);
    nbuf_del(chan->snd_buf);
    close(chan->fd);
    free(chan);
}

int tcp_chan_get_read_buf_size(tcp_chan_t *chan)
{
    return nbuf_size(chan->rcv_buf);
}

int tcp_chan_read_buf_empty(tcp_chan_t * chan)
{
    return nbuf_empty(chan->rcv_buf);
}

int tcp_chan_read(tcp_chan_t *chan, void *data, int size)
{
    return nbuf_remove(chan->rcv_buf, data, size);
}

char tcp_chan_readc(tcp_chan_t *chan)
{
    return nbuf_removec(chan->rcv_buf);
}

int tcp_chan_peek(tcp_chan_t *chan, void *data, int size)
{
    return nbuf_peek(chan->rcv_buf, data, size);
}

char tcp_chan_peekc(tcp_chan_t *chan)
{
    return nbuf_peekc(chan->rcv_buf);
}

int tcp_chan_get_write_buf_size(tcp_chan_t *chan)
{
    return nbuf_size(chan->snd_buf);
}

int tcp_chan_write_buf_empty(tcp_chan_t * chan)
{
    return nbuf_empty(chan->snd_buf);
}

int tcp_chan_write(tcp_chan_t *chan, const void *data, int size)
{
    nbuf_append(chan->snd_buf, data, size);
    update_chan_events(chan);
    return size;
}

int tcp_chan_get_peername(tcp_chan_t *chan, struct sockaddr *addr, int addrlen)
{
    memcpy(addr, &chan->addr, addrlen);
    return 0;
}

int tcp_chan_fd(tcp_chan_t *chan)
{
    return chan->fd;
}

void tcp_chan_set_userdata(tcp_chan_t *chan, void *udata)
{
    chan->udata = udata;
}

void *tcp_chan_get_userdata(tcp_chan_t *chan)
{
    return chan->udata;
}

void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    int n, iov_cnt, err = 0;
    struct iovec iov[2];
    tcp_chan_t *chan = udata;
    if (chan->flags & TCP_CHAN_ERROR)
        return;

    chan->flags |= TCP_CHAN_IN_EVENT_CB;
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
        iov_cnt = ARRAY_SIZE(iov);
        nbuf_reserve(chan->rcv_buf, iov, &iov_cnt);
read_again:
        n = readv(fd, iov, iov_cnt);
        //LLOG(LL_TRACE, "read fd %d, ret=%d", fd, n);
        if (n == 0) {
            err = 0;
            chan->flags |= TCP_CHAN_ERROR;
        } else if (n == -1) {
            if (errno == EINTR)
                goto read_again;
            if (errno != EAGAIN) {
                err = -errno;
                chan->flags |= TCP_CHAN_ERROR;
                LLOG(LL_ERROR, "read fd %d error: %s.", fd, strerror(errno));
            }
        }
        if (n > 0) {
            nbuf_commit(chan->rcv_buf, n);
            if (chan->read_cb)
                chan->read_cb(chan, chan->udata);
        }
    }
    if (chan->loop
        && !(chan->flags & TCP_CHAN_ERROR)
        && (events & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {

        if (chan->flags & TCP_CHAN_CONNECTING) {
            chan->flags &= ~TCP_CHAN_CONNECTING;
            err = get_socket_error(chan->fd);
            if (err == 0) {
                /* Connected */
                if (chan->error_cb)
                    chan->error_cb(chan, 1, chan->udata);
            } else {
                err = -err;
                chan->flags |= TCP_CHAN_ERROR;
            }
        } else if (!nbuf_empty(chan->snd_buf)) {
            int old, iov_cnt;
write_again:
            old = nbuf_size(chan->snd_buf);
            iov_cnt = nbuf_peekv(chan->snd_buf, iov, ARRAY_SIZE(iov), &old);
            assert(iov_cnt > 0);
            if (iov_cnt == 1)
                n = write(fd, iov[0].iov_base, iov[0].iov_len);
            else
                n = writev(fd, iov, iov_cnt);
            if (n > 0) {
                nbuf_consume(chan->snd_buf, n);
            } else if (n == -1) {
                if (errno == EINTR) {
                    LLOG(LL_TRACE, "EINTR");
                    goto write_again;
                }
                if (errno != EAGAIN) {
                    LLOG(LL_ERROR, "write fd %d error: %s.", fd, strerror(errno));
                    err = -errno;
                    chan->flags |= TCP_CHAN_ERROR;
                }
            }
            if (n > 0) {
                if (chan->write_cb)
                    chan->write_cb(chan, chan->udata);
            }
        }
    }

    if (chan->loop && (chan->flags & TCP_CHAN_ERROR)) {
        if (chan->error_cb)
            chan->error_cb(chan, err, chan->udata);
    }

    update_chan_events(chan);
    chan->flags &= ~TCP_CHAN_IN_EVENT_CB;

    /* check deferred close */
    if (chan->loop && (chan->flags & TCP_CHAN_CLOSING)) {
        if (nbuf_empty(chan->snd_buf))
            tcp_chan_close(chan, 0);
    }
}

void update_chan_events(tcp_chan_t* chan)
{
    if (!chan->loop)
        return;
    int pevents = 0;
    if (!(chan->flags & TCP_CHAN_ERROR)) {
        if (!(chan->flags & TCP_CHAN_CLOSING))
            pevents |= EPOLLIN;
        if ((chan->flags & TCP_CHAN_CONNECTING) || !nbuf_empty(chan->snd_buf))
            pevents |= EPOLLOUT;
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

void srv_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    tcp_srv_t *srv = udata;
    tcp_chan_t *chan = tcp_chan_accept(loop, fd);
    if (!chan)
        return;
    if (!srv->accept_cb) {
        tcp_chan_close(chan, 0);
        return;
    }
    //LLOG(LL_TRACE, "accept %p", chan);
    srv->accept_cb(srv, chan, srv->udata);
}

tcp_chan_t *tcp_connect(zl_loop_t *loop, const char *ip, unsigned port)
{
    struct sockaddr_in *addr;
    int ret;
    tcp_chan_t *chan = malloc(sizeof(tcp_chan_t));
    memset(chan, 0, sizeof(tcp_chan_t));
    chan->loop = loop;
    chan->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (chan->fd == -1)
        goto err_out;
    //LLOG(LL_TRACE, "new fd %d", chan->fd);
    set_tcp_nodelay(chan->fd, 1);
    //set_socket_send_buf_size(chan->fd, 8192);
    chan->rcv_buf = nbuf_new1(TCP_CHAN_RCV_BUF_SIZE);
    chan->snd_buf = nbuf_new1(TCP_CHAN_SND_BUF_SIZE);

    chan->flags |= TCP_CHAN_CONNECTING;
    addr = (struct sockaddr_in*)&chan->addr;
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr->sin_addr);
    ret = connect(chan->fd, (struct sockaddr*)addr, sizeof(struct sockaddr_in));
    assert(ret == -1);
    assert(errno == EINPROGRESS);

    update_chan_events(chan);
    return chan;
err_out:
    free(chan);
    return NULL;
}

void tcp_chan_detach(tcp_chan_t *chan)
{
    if (chan->eevents)
        zl_fd_ctl(chan->loop, EPOLL_CTL_DEL, chan->fd, 0, NULL, NULL);
    chan->loop = NULL;
    WRITE_FENCE;
}

void tcp_chan_attach(tcp_chan_t *chan, zl_loop_t *loop)
{
    chan->loop = loop;
    if (chan->eevents)
        zl_fd_ctl(chan->loop, EPOLL_CTL_ADD, chan->fd, chan->eevents, chan_fd_event_handler, chan);

    chan->flags |= TCP_CHAN_IN_EVENT_CB;
    if (!(chan->flags & TCP_CHAN_ERROR)) {
        if (chan->read_cb)
            chan->read_cb(chan, chan->udata);
    }
    if (chan->loop
        && !(chan->flags & TCP_CHAN_ERROR)) {
        if (chan->write_cb)
            chan->write_cb(chan, chan->udata);
    }
    if (chan->loop
        && (chan->flags & TCP_CHAN_ERROR)) {
        if (chan->error_cb)
            chan->error_cb(chan, -1, chan->udata);
    }
    update_chan_events(chan);
    chan->flags &= ~TCP_CHAN_IN_EVENT_CB;
    /* check deferred close */
    if (chan->loop && (chan->flags & TCP_CHAN_CLOSING)) {
        if (nbuf_empty(chan->snd_buf))
            tcp_chan_close(chan, 0);
    }
}
