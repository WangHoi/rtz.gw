#include "tcp_chan_ssl.h"
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
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

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

struct tcp_srv_ssl_t {
    zl_loop_t *loop;
    int fd;
    struct sockaddr_storage addr;
    tcp_srv_ssl_accept_cb accept_cb;
    void *udata;
    int flags;
};

struct tcp_chan_ssl_t {
    zl_loop_t *loop;
    int fd;
    struct sockaddr_storage addr;
    nbuf_t *rcv_buf;
    nbuf_t *snd_buf;
    tcp_chan_ssl_buffer_cb read_cb;
    tcp_chan_ssl_buffer_cb write_cb;
    tcp_chan_ssl_event_cb error_cb;

    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;

    void *udata;
    int eevents;
    int flags;
};

static const char *SSL_CIPHERS = "HIGH:!aNULL:!MD5:!RC4";

static SSL_CTX *ssl_ctx = NULL;
static X509 *ssl_cert = NULL;
static EVP_PKEY *ssl_key = NULL;
static char local_fingerprint[160];

static void srv_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata);
static void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata);
static void update_chan_events(tcp_chan_ssl_t* chan);

static int ssl_load_keys(const char *server_pem, const char *server_key, const char *password,
                          X509 **certificate, EVP_PKEY **private_key);
static int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
static void ssl_callback(const SSL *ssl, int where, int ret);

int tcp_ssl_init(const char *pem, const char *key, const char *pwd)
{
    ssl_ctx = SSL_CTX_new(TLS_method());
    if (!ssl_ctx) {
        LLOG(LL_FATAL, "Ops, error creating SSL context.");
        return -1;
    }
    //SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, ssl_verify_callback);
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, ssl_verify_callback);
    if (!pem || !key) {
        LLOG(LL_FATAL, "SSL certificate and key must be specified.");
        return -2;
    }
    if (ssl_load_keys(pem, key, pwd, &ssl_cert, &ssl_key) != 0)
        return -3;

    if (!SSL_CTX_use_certificate(ssl_ctx, ssl_cert)) {
        LLOG(LL_FATAL, "Certificate error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -4;
    }
    if (!SSL_CTX_use_PrivateKey(ssl_ctx, ssl_key)) {
        LLOG(LL_FATAL, "Certificate key error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -5;
    }
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        LLOG(LL_FATAL, "Certificate check error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -6;
    }
    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    unsigned int size;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    if (X509_digest(ssl_cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
        LLOG(LL_FATAL, "Error converting X509 structure (%s).", ERR_reason_error_string(ERR_get_error()));
        return -7;
    }
    char *lfp = (char *)&local_fingerprint;
    unsigned int i = 0;
    for (i = 0; i < size; i++) {
        snprintf(lfp, 4, "%.2X:", fingerprint[i]);
        lfp += 3;
    }
    *(lfp - 1) = 0;
    LLOG(LL_INFO, "SSL: Fingerprint of our certificate: %s.", local_fingerprint);
    //SSL_CTX_set_cipher_list(ssl_ctx, SSL_CIPHERS);

    return 0;
}

void tcp_ssl_cleanup()
{
    if (ssl_cert != NULL) {
        X509_free(ssl_cert);
        ssl_cert = NULL;
    }
    if (ssl_key != NULL) {
        EVP_PKEY_free(ssl_key);
        ssl_key = NULL;
    }
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
}

tcp_srv_ssl_t *tcp_srv_ssl_new(zl_loop_t *loop)
{
    tcp_srv_ssl_t *srv = malloc(sizeof(tcp_srv_ssl_t));
    memset(srv, 0, sizeof(tcp_srv_ssl_t));
    srv->loop = loop;
    srv->fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    set_socket_reuseport(srv->fd, 1);
    return srv;
}
void tcp_srv_ssl_set_cb(tcp_srv_ssl_t *srv, tcp_srv_ssl_accept_cb accept_cb, void *udata)
{
    srv->accept_cb = accept_cb;
    srv->udata = udata;
}
int tcp_srv_ssl_bind(tcp_srv_ssl_t *srv, const char *ip, unsigned short port)
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

int tcp_srv_ssl_listen(tcp_srv_ssl_t *srv)
{
    zl_fd_ctl(srv->loop, EPOLL_CTL_ADD, srv->fd, EPOLLIN, srv_fd_event_handler, srv);
    return listen(srv->fd, 511);
}

void tcp_srv_ssl_del(tcp_srv_ssl_t *srv)
{
    zl_fd_ctl(srv->loop, EPOLL_CTL_DEL, srv->fd, 0, NULL, NULL);
    close(srv->fd);
    free(srv);
}

tcp_chan_ssl_t *tcp_chan_ssl_accept(zl_loop_t *loop, int listenfd)
{
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    tcp_chan_ssl_t *chan = malloc(sizeof(tcp_chan_ssl_t));
    memset(chan, 0, sizeof(tcp_chan_ssl_t));
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

    chan->ssl = SSL_new(ssl_ctx);
    SSL_set_accept_state(chan->ssl);
    SSL_set_ex_data(chan->ssl, 0, chan);
    SSL_set_info_callback(chan->ssl, ssl_callback);
    chan->read_bio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(chan->read_bio, -1);
    chan->write_bio = BIO_new(BIO_s_mem());
    SSL_set_bio(chan->ssl, chan->read_bio, chan->write_bio);
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_set_options(chan->ssl, flags);
    SSL_do_handshake(chan->ssl);

    update_chan_events(chan);
    return chan;

err_out:
    free(chan);
    return NULL;
}

void tcp_chan_ssl_set_cb(tcp_chan_ssl_t *chan, tcp_chan_ssl_buffer_cb read_cb,
                         tcp_chan_ssl_buffer_cb write_cb, tcp_chan_ssl_event_cb error_cb,
                         void *udata)
{
    chan->read_cb = read_cb;
    chan->write_cb = write_cb;
    chan->error_cb = error_cb;
    chan->udata = udata;
}

void tcp_chan_ssl_close(tcp_chan_ssl_t *chan, int flush_write)
{
    tcp_chan_ssl_set_cb(chan, NULL, NULL, NULL, NULL);

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
        zl_fd_ctl(chan->loop, EPOLL_CTL_DEL, chan->fd, 0, NULL, NULL);
    }

    SSL_free(chan->ssl);
    /* BIOs freed by SSL_free */
    chan->read_bio = NULL;
    chan->write_bio = NULL;

    nbuf_del(chan->rcv_buf);
    nbuf_del(chan->snd_buf);
    close(chan->fd);
    free(chan);
}

int tcp_chan_ssl_get_read_buf_size(tcp_chan_ssl_t *chan)
{
    return nbuf_size(chan->rcv_buf);
}

int tcp_chan_ssl_read_buf_empty(tcp_chan_ssl_t * chan)
{
    return nbuf_empty(chan->rcv_buf);
}

int tcp_chan_ssl_read(tcp_chan_ssl_t *chan, void *data, int size)
{
    return nbuf_remove(chan->rcv_buf, data, size);
}

char tcp_chan_ssl_readc(tcp_chan_ssl_t *chan)
{
    return nbuf_removec(chan->rcv_buf);
}

int tcp_chan_ssl_peek(tcp_chan_ssl_t *chan, void *data, int size)
{
    return nbuf_peek(chan->rcv_buf, data, size);
}

char tcp_chan_ssl_peekc(tcp_chan_ssl_t *chan)
{
    return nbuf_peekc(chan->rcv_buf);
}

int tcp_chan_ssl_get_write_buf_size(tcp_chan_ssl_t *chan)
{
    return nbuf_size(chan->snd_buf);
}

int tcp_chan_ssl_write_buf_empty(tcp_chan_ssl_t * chan)
{
    return nbuf_empty(chan->snd_buf);
}

int tcp_chan_ssl_write(tcp_chan_ssl_t *chan, const void *data, int size)
{
    int n = SSL_write(chan->ssl, data, size);
    if (n > 0) {
        if (n < size)
            LLOG(LL_ERROR, "partial write %d %d", n, size);
        struct iovec iov[1];
        int iov_cnt;
        do {
            iov_cnt = ARRAY_SIZE(iov);
            nbuf_reserve(chan->snd_buf, iov, &iov_cnt);
            n = BIO_read(chan->write_bio, iov[0].iov_base, iov[0].iov_len);
            LLOG(LL_TRACE, "write_bio %p ret=%d", iov[0].iov_base, n);
            if (n > 0)
                nbuf_commit(chan->snd_buf, n);
        } while (n > 0);
        update_chan_events(chan);
    } else {
        int err = SSL_get_error(chan->ssl, n);
        LLOG(LL_ERROR, "write ret %d error %d", n, err);
    }
    return size;
}

int tcp_chan_ssl_get_peername(tcp_chan_ssl_t *chan, struct sockaddr *addr, int addrlen)
{
    memcpy(addr, &chan->addr, addrlen);
    return 0;
}

int tcp_chan_ssl_fd(tcp_chan_ssl_t *chan)
{
    return chan->fd;
}

void chan_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    int n, iov_cnt, len, err = 0;
    struct iovec iov[1];
    unsigned char buf[TCP_CHAN_RCV_BUF_SIZE], *p;
    tcp_chan_ssl_t *chan = udata;
    if (chan->flags & TCP_CHAN_ERROR)
        return;

    chan->flags |= TCP_CHAN_IN_EVENT_CB;
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
read_again:
        n = read(fd, buf, sizeof(buf));
        LLOG(LL_TRACE, "read fd %d, ret=%d", fd, n);
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
        p = buf;
        len = n;
        while (len > 0) {
            n = BIO_write(chan->read_bio, p, len);
            if (n <= 0)
                break;
            p += n;
            len -= n;
            iov_cnt = 1;
            nbuf_reserve(chan->rcv_buf, iov, &iov_cnt);
            n = SSL_read(chan->ssl, iov[0].iov_base, iov[0].iov_len);
            if (n > 0) {
                nbuf_commit(chan->rcv_buf, n);
                if (chan->read_cb)
                    chan->read_cb(chan, chan->udata);
            } else if (n < 0) {
                err = SSL_get_error(chan->ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_READ) {
                    do {
                        iov_cnt = 1;
                        nbuf_reserve(chan->snd_buf, iov, &iov_cnt);
                        if (iov_cnt > 0) {
                            n = BIO_read(chan->write_bio, iov[0].iov_base, iov[0].iov_len);
                            if (n > 0)
                                nbuf_commit(chan->snd_buf, n);
                        }
                    } while (iov_cnt > 0 && n > 0);
                } else if (err != SSL_ERROR_NONE) {
                    err = -EPROTO;
                    break;
                }
            }
        }
    }
    if (!(chan->flags & TCP_CHAN_ERROR)
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
            iov_cnt = nbuf_peekv(chan->snd_buf, iov, 1/*ARRAY_SIZE(iov)*/, NULL/*&old*/);
            assert(iov_cnt > 0);
            if (iov_cnt == 1)
                n = write(fd, iov[0].iov_base, iov[0].iov_len);
            else
                n = writev(fd, iov, iov_cnt);
            LLOG(LL_TRACE, "write ret %d", n);
            if (n > 0) {
                nbuf_consume(chan->snd_buf, n);
            } else if (n == -1) {
                if (errno == EINTR) {
                    LLOG(LL_TRACE, "EINTR");
                    /*goto write_again;*/
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

    if (chan->flags & TCP_CHAN_ERROR) {
        if (chan->error_cb)
            chan->error_cb(chan, err, chan->udata);
    }

    update_chan_events(chan);
    chan->flags &= ~TCP_CHAN_IN_EVENT_CB;

    /* check deferred close */
    if (chan->flags & TCP_CHAN_CLOSING) {
        if (nbuf_empty(chan->snd_buf))
            tcp_chan_ssl_close(chan, 0);
    }
}

void update_chan_events(tcp_chan_ssl_t* chan)
{
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
    tcp_srv_ssl_t *srv = udata;
    tcp_chan_ssl_t *chan = tcp_chan_ssl_accept(loop, fd);
    if (!chan)
        return;
    if (!srv->accept_cb) {
        tcp_chan_ssl_close(chan, 0);
        return;
    }
    //LLOG(LL_TRACE, "accept %p", chan);
    srv->accept_cb(srv, chan, srv->udata);
}

tcp_chan_ssl_t *tcp_chan_ssl_connect(zl_loop_t *loop, const char *ip, unsigned port)
{
    struct sockaddr_in *addr;
    int ret;
    tcp_chan_ssl_t *chan = malloc(sizeof(tcp_chan_ssl_t));
    memset(chan, 0, sizeof(tcp_chan_ssl_t));
    chan->loop = loop;
    chan->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (chan->fd == -1)
        goto err_out;
    //LLOG(LL_TRACE, "new fd %d", chan->fd);
    set_tcp_nodelay(chan->fd, 1);
    set_socket_send_buf_size(chan->fd, 8192);
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

int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    /* We just use the verify_callback to request a certificate from the client */
    return 1;
}

int ssl_load_keys(const char *server_pem, const char *server_key, const char *password,
                  X509 **certificate, EVP_PKEY **private_key)
{
    FILE *f = NULL;

    f = fopen(server_pem, "r");
    if (!f) {
        LLOG(LL_FATAL, "Error opening certificate file.");
        goto error;
    }
    *certificate = PEM_read_X509(f, NULL, NULL, NULL);
    if (!*certificate) {
        LLOG(LL_FATAL, "PEM_read_X509 failed.");
        goto error;
    }
    fclose(f);

    f = fopen(server_key, "r");
    if (!f) {
        LLOG(LL_FATAL, "Error opening key file.");
        goto error;
    }
    *private_key = PEM_read_PrivateKey(f, NULL, NULL, (void *)password);
    if (!*private_key) {
        LLOG(LL_FATAL, "PEM_read_PrivateKey failed.");
        goto error;
    }
    fclose(f);

    return 0;

error:
    if (*certificate) {
        X509_free(*certificate);
        *certificate = NULL;
    }
    if (*private_key) {
        EVP_PKEY_free(*private_key);
        *private_key = NULL;
    }
    return -1;
}

void ssl_callback(const SSL *ssl, int where, int ret)
{
#if 0
    /* We only care about alerts */
    //LLOG(LL_TRACE, "dtls callback where=%04x ret=%d", where, ret);
    if (!(where & SSL_CB_ALERT)) {
        return;
    }
    dtls_srtp *dtls = SSL_get_ex_data(ssl, 0);
    if (!dtls) {
        LLOG(LL_ERROR, "No DTLS session related to this alert...");
        return;
    }
    ice_component_t *component = dtls->component;
    if (component == NULL) {
        LLOG(LL_ERROR, "No ICE component related to this alert...");
        return;
    }
    ice_stream_t *stream = ice_component_get_stream(component);
    if (!stream) {
        LLOG(LL_ERROR, "No ICE stream related to this alert...");
        return;
    }
    ice_agent_t *handle = ice_stream_get_agent(stream);
    if (!handle) {
        LLOG(LL_ERROR, "No ICE handle related to this alert...");
        return;
    }
    LLOG(LL_TRACE, "DTLS alert triggered on stream (component), closing...");
    ice_webrtc_hangup(handle, "DTLS alert");
#endif
}
