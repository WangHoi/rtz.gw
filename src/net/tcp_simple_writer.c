#include "tcp_simple_writer.h"
#include "nbuf.h"
#include "macro_util.h"
#include "log.h"
#include <sys/uio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

struct tcp_simple_writer_t {
    tcp_chan_t *chan;
    nbuf_t *buf;
};

static size_t count_iov_size(struct iovec *iov, int iov_cnt)
{
    size_t n = 0;
    while (iov_cnt--)
        n += iov[iov_cnt].iov_len;
    return n;
}

tcp_simple_writer_t *tcp_simple_writer_new(tcp_chan_t *chan)
{
    tcp_simple_writer_t *w = malloc(sizeof(tcp_simple_writer_t));
    w->chan = chan;
    w->buf = nbuf_new();
    return w;
}
int tcp_simple_writer_perform(tcp_simple_writer_t *w, const void *data, int size)
{
    int ret;
    if (!nbuf_empty(w->buf)) {
        nbuf_append(w->buf, data, size);
        return 0;
    }
    int n = tcp_chan_write(w->chan, data, size);
    if (n == -1 && errno != EAGAIN)
        return -1;
    if (n < size) {
        if (n < 0)
            n = 0;
        nbuf_append(w->buf, (const char*)data + n, size - n);
        tcp_chan_enable_poll_writable(w->chan, 1);
    }
    return n;
}
int tcp_simple_writer_performv(tcp_simple_writer_t *w, struct iovec *iov, int iov_cnt)
{
    if (!nbuf_empty(w->buf)) {
        int i;
        for (i = 0; i < iov_cnt; ++i)
            nbuf_append(w->buf, iov[i].iov_base, iov[i].iov_len);
        return 0;
    }

    size_t total_size = count_iov_size(iov, iov_cnt);
    int n = tcp_chan_writev(w->chan, iov, iov_cnt);
    if (n == -1 && errno != EAGAIN)
        return -1;
    if (n == total_size)
        return n;

    if (n < 0)
        n = 0;
    int ret = n;
    while (n > 0 && iov_cnt > 0) {
        int m = MIN(n, (int)iov->iov_len);
        iov->iov_base += m;
        iov->iov_len -= m;
        n -= m;
        if (iov->iov_len > 0)
            break;
        ++iov;
        --iov_cnt;
    }
    if (iov_cnt > 0) {
        while (iov_cnt > 0) {
            nbuf_append(w->buf, iov->iov_base, iov->iov_len);
            ++iov;
            --iov_cnt;
        }
        tcp_chan_enable_poll_writable(w->chan, 1);
    }
    return ret;
}
void tcp_simple_writer_sent_notify(tcp_simple_writer_t *w)
{
    struct iovec iov[8];
    int iov_cnt = nbuf_peekv(w->buf, iov, ARRAY_SIZE(iov), NULL);
    if (iov_cnt > 0) {
        int n = tcp_chan_writev(w->chan, iov, iov_cnt);
        if (n > 0)
            nbuf_consume(w->buf, n);
    }
    if (nbuf_empty(w->buf))
        tcp_chan_enable_poll_writable(w->chan, 0);
}

int tcp_simple_writer_buf_size(tcp_simple_writer_t *w)
{
    return nbuf_size(w->buf);
}

void tcp_simple_writer_del(tcp_simple_writer_t *w)
{
    tcp_chan_enable_poll_writable(w->chan, 0);
    nbuf_del(w->buf);
    free(w);
}
