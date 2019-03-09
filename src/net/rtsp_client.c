#include "rtsp_client.h"
#include "event_loop.h"
#include "sbuf.h"
#include "net_util.h"
#include "log.h"
#include "base64.h"
#include "md5.h"
#include "list.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>

typedef enum rtsp_auth_type_t {
    RTSP_AUTH_BASIC,
    RTSP_AUTH_DIGEST,
} rtsp_auth_type_t;

typedef enum rtsp_parse_state_t {
    RTSP_PARSE_INIT,
    RTSP_PARSE_INTERLEAVED_HEADER,
    RTSP_PARSE_INTERLEAVED_CONTENT,
    RTSP_PARSE_HEADER,
    RTSP_PARSE_CONTENT,
    NUM_RTSP_PARSE_STATES,
} rtsp_parse_state_t;

enum {
    RTSP_CLIENT_URI_SIZE = 4096,
    RTSP_CLIENT_IP_SIZE = 64,
    RTSP_CLIENT_USER_SIZE = 128,
    RTSP_CLIENT_PWD_SIZE = 128,
    RTSP_CLIENT_RCV_BUF_SIZE = 65536,
    RTSP_CLIENT_SND_BUF_SIZE = 65536,
    RTSP_CLIENT_DEFAULT_PORT = 554,
    RTSP_CLIENT_TIMEOUT_MSECS = 3000,
};

enum rtsp_client_flag {
    RTSP_CLIENT_IN_EVENT_CB = 1,
    RTSP_CLIENT_ERROR = 2,
};

struct rtsp_client_t {
    zl_loop_t* loop;
    int flag;

    sbuf_t *uri;
    sbuf_t *user;
    sbuf_t *pwd;
    sbuf_t *ip;
    unsigned short port;

    rtsp_parse_state_t pstate;
    int expected_plen;
    int next_cseq;
    rtsp_auth_type_t auth_type;
    sbuf_t *auth_basic_cache;
    sbuf_t *auth_basic_line_cache;
    sbuf_t *auth_realm;
    sbuf_t *auth_nonce;
    sbuf_t *auth_digest_line_cache;
    sbuf_t *session;
    sbuf_t *sdp;

    void *udata;
    long long connect_timestamp;
    zl_defer_cb connect_cb;
    rtp_packet_cb packet_cb;
    struct list_head request_list;

    int fd;
    uint32_t eevents;
    sbuf_t *rcv_buf;
    sbuf_t *snd_buf;
    int sent_size;

    struct list_head timeout_link;
};

typedef struct rtsp_request_t rtsp_request_t;
typedef void (*rtsp_request_cb)(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);

typedef struct rtsp_header_t {
    const char *name;
    sbuf_t *value;
    struct list_head link;
} rtsp_header_t;

struct rtsp_request_t {
    rtsp_client_t *client;
    long long timestamp;
    const char *method;
    sbuf_t *uri;
    rtsp_request_cb cb;
    zl_defer_cb ucb;
    struct list_head header_list;
    struct list_head link;
};

static rtsp_request_t *rtsp_request_new(rtsp_client_t *client, const char *method,
                                        rtsp_request_cb func, zl_defer_cb ucb);
static void add_request(rtsp_client_t *client, rtsp_request_t *req);
static void add_header(rtsp_request_t *req, const char *name, const char *value_format, ...)
    __attribute__((format(printf, 3, 4)));
static void rtsp_request_del(rtsp_request_t *req);
static void connect_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);
static void client_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);
static void recv_handler(rtsp_client_t *client, const char *data, int size);
static void rtp_packet_handler(rtsp_client_t *client, const char *data, int size);
static void request_reply_handler(rtsp_client_t *client, const char *data, int size);
static void describe_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void setup_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void play_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void pause_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void teardown_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void options_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size);
static void send_options(rtsp_client_t *client, zl_defer_cb cb);
static void send_describe(rtsp_client_t *client, zl_defer_cb cb);
static void send_setup(rtsp_client_t *client, const char *control, zl_defer_cb cb);
static void send_play(rtsp_client_t *client, zl_defer_cb cb);
static void send_pause(rtsp_client_t *client, zl_defer_cb cb);
static void send_teardown(rtsp_client_t *client, zl_defer_cb cb);
static void update_auth_info(rtsp_client_t *client, const char *data, size_t size);
static void buffer_request_to_send(rtsp_client_t *client, rtsp_request_t *req);
static const char *get_auth_line(rtsp_client_t *client, const char *method);
static void update_poll_events(rtsp_client_t *client);
static void error_handler(rtsp_client_t *client, int err);
static long long rtsp_client_get_timestamp(rtsp_client_t *client);
static void rtsp_client_timeout_check(rtsp_client_t *client, long long now);

static LIST_HEAD(timeout_check_list);

rtsp_client_t *rtsp_client_new(zl_loop_t *loop)
{
    rtsp_client_t* client = malloc(sizeof(rtsp_client_t));
    memset(client, 0, sizeof(rtsp_client_t));
    client->loop = loop;
    client->flag = 0;
    client->udata = client;
    client->uri = sbuf_new1(RTSP_CLIENT_URI_SIZE);
    client->ip = sbuf_new1(RTSP_CLIENT_IP_SIZE);
    client->user = sbuf_new1(RTSP_CLIENT_USER_SIZE);
    client->pwd = sbuf_new1(RTSP_CLIENT_PWD_SIZE);
    client->pstate = RTSP_PARSE_INIT;
    client->expected_plen = 0;
    client->fd = -1;
    client->rcv_buf = sbuf_new(RTSP_CLIENT_RCV_BUF_SIZE);
    client->snd_buf = sbuf_new(RTSP_CLIENT_SND_BUF_SIZE);
    client->sent_size = 0;
    client->next_cseq = 1;
    client->auth_type = RTSP_AUTH_BASIC;
    client->auth_basic_line_cache = sbuf_new();
    client->auth_digest_line_cache = sbuf_new();
    client->auth_basic_cache = sbuf_new();
    client->auth_nonce = sbuf_new();
    client->auth_realm = sbuf_new();
    client->session = sbuf_new();
    client->sdp = sbuf_new();
    client->eevents = 0;
    client->packet_cb = NULL;
    INIT_LIST_HEAD(&client->request_list);
    list_add_tail(&client->timeout_link, &timeout_check_list);
    return client;
}

void rtsp_client_set_userdata(rtsp_client_t *client, void *udata)
{
    client->udata = udata;
}

void rtsp_client_del(rtsp_client_t *client)
{
    sbuf_del(client->uri);
    sbuf_del(client->ip);
    sbuf_del(client->user);
    sbuf_del(client->pwd);
    sbuf_del(client->rcv_buf);
    sbuf_del(client->snd_buf);
    sbuf_del(client->auth_basic_line_cache);
    sbuf_del(client->auth_digest_line_cache);
    sbuf_del(client->auth_basic_cache);
    sbuf_del(client->auth_realm);
    sbuf_del(client->auth_nonce);
    sbuf_del(client->session);
    sbuf_del(client->sdp);
    list_del(&client->timeout_link);
    free(client);
}

void rtsp_client_set_uri(rtsp_client_t *client, const char *uri)
{
    sbuf_strcpy(client->uri, uri);
    char *ip = NULL;
    int n;
    n = sscanf(client->uri->data, "rtsp://%m[0-9.]:%hu", &ip, &client->port);
    if (n >= 1)
        sbuf_strcpy(client->ip, ip);
    if (n < 2)
        client->port = RTSP_CLIENT_DEFAULT_PORT;
    free(ip);
}
void rtsp_client_set_user(rtsp_client_t *client, const char *user)
{
    sbuf_strcpy(client->user, user);
}
void rtsp_client_set_password(rtsp_client_t *client, const char *pwd)
{
    sbuf_strcpy(client->pwd, pwd);
}

void rtsp_client_set_packet_cb(rtsp_client_t *client, rtp_packet_cb func)
{
    client->packet_cb = func;
}

const char *rtsp_client_get_sdp(rtsp_client_t *client)
{
    return client->sdp->data;
}
void rtsp_client_connect(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    struct sockaddr_in addr = {};
    int ret;
    client->connect_timestamp = zl_timestamp();
    client->connect_cb = func;
    client->fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    addr.sin_family = AF_INET;
    ret = inet_pton(AF_INET, client->ip->data, &addr.sin_addr);
    addr.sin_port = htons(client->port);
    ret = connect(client->fd, &addr, sizeof(addr));
    LLOG(LL_TRACE, "connect ret=%d errno=%s.", ret, (ret == 0) ? "" : strerror(errno));
    client->eevents = EPOLLOUT;
    zl_fd_ctl(client->loop, EPOLL_CTL_ADD, client->fd, client->eevents, &connect_handler, client);
}

void rtsp_client_options(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_options(client, func);
}

void rtsp_client_describe(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_describe(client, func);
}

void rtsp_client_setup(rtsp_client_t *client, const char *control, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_setup(client, control, func);
}

void rtsp_client_play(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_play(client, func);
}
void rtsp_client_pause(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_pause(client, func);
}
void rtsp_client_close(rtsp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_pause(client, func);
}

void rtsp_client_abort(rtsp_client_t *client)
{
    error_handler(client, -ECANCELED);
    if (client->fd != -1) {
        if (client->eevents) {
            client->eevents = 0;
            zl_fd_ctl(client->loop, EPOLL_CTL_DEL, client->fd, 0, NULL, client->udata);
        }
        close(client->fd);
        client->fd = -1;
    }
    client->flag &= ~RTSP_CLIENT_ERROR;
}

void connect_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    if (!(events & (EPOLLOUT | EPOLLHUP | EPOLLERR)))
        return;
    rtsp_client_t* client = udata;
    client->flag |= RTSP_CLIENT_IN_EVENT_CB;
    int err = get_socket_error(fd);
    if (err == 0) {
        uint32_t pevents = EPOLLIN;
        if (!sbuf_empty(client->snd_buf))
            pevents |= EPOLLOUT;
        if (pevents != client->eevents) {
            client->eevents = pevents;
            zl_fd_ctl(loop, EPOLL_CTL_MOD, fd, pevents, client_handler, client);
        }
    } else {
        client->flag |= RTSP_CLIENT_ERROR;
        client->eevents = 0;
        zl_fd_ctl(loop, EPOLL_CTL_DEL, fd, 0, NULL, client);
    }
    if (client->connect_cb) {
        zl_defer_cb cb = client->connect_cb;
        client->connect_cb = NULL;
        cb(client->loop, -err, client->udata);
    }
    if (client->flag & RTSP_CLIENT_ERROR) {
        error_handler(client, -EINVAL);
    } else {
        zl_defer_cb cb = client->connect_cb;
        client->connect_cb = NULL;
        cb(client->loop, 0, client->udata);
    }
    client->flag &= ~RTSP_CLIENT_IN_EVENT_CB;
}

void client_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    rtsp_client_t *client = udata;
    client->flag |= RTSP_CLIENT_IN_EVENT_CB;
    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
        char *buf = malloc(RTSP_CLIENT_RCV_BUF_SIZE);
        int n = RTSP_CLIENT_RCV_BUF_SIZE;
read_again:
        n = read(fd, buf, n);
        if (n == -1) {
            if (errno == EINTR) {
                goto read_again;
            } else {
                LLOG(LL_TRACE, "client %d read err: %s", fd, strerror(errno));
                client->flag |= RTSP_CLIENT_ERROR;
            }
        } else if (n == 0) {
            LLOG(LL_TRACE, "client %d eof", fd);
            client->flag |= RTSP_CLIENT_ERROR;
        } else {
            recv_handler(client, buf, n);
        }
        free(buf);
    }
    if (events & (EPOLLOUT | EPOLLHUP | EPOLLERR)) {
        if (client->sent_size < client->snd_buf->size) {
            char *buf = client->snd_buf->data + client->sent_size;
            int n = client->snd_buf->size - client->sent_size;
write_again:
            n = write(fd, buf, n);
            if (n == -1) {
                if (errno == EINTR) {
                    goto write_again;
                } else {
                    LLOG(LL_TRACE, "client %d write err: %s", fd, strerror(errno));
                    client->flag |= RTSP_CLIENT_ERROR;
                }
            } else {
                client->sent_size += n;
                if (client->sent_size == client->snd_buf->size) {
                    sbuf_clear(client->snd_buf);
                    client->sent_size = 0;
                }
            }
        }
    }
    update_poll_events(client);
    if (client->flag & RTSP_CLIENT_ERROR)
        error_handler(client, -EINVAL);
    client->flag &= ~RTSP_CLIENT_IN_EVENT_CB;
}

void send_describe(rtsp_client_t* client, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "DESCRIBE", describe_handler, cb);
    add_request(client, req);
}

void send_setup(rtsp_client_t* client, const char *control, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "SETUP", setup_handler, cb);
    sbuf_appendc(req->uri, '/');
    sbuf_append1(req->uri, control);
    add_header(req, "Transport", "RTP/AVP/TCP;interleaved=%d-%d", 0, 1);
    add_request(client, req);
}

void send_play(rtsp_client_t* client, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "PLAY", play_handler, cb);
    add_request(client, req);
}

void send_pause(rtsp_client_t* client, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "PAUSE", pause_handler, cb);
    add_request(client, req);
}

void send_teardown(rtsp_client_t* client, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "TEARDOWN", teardown_handler, cb);
    add_request(client, req);
}

void send_options(rtsp_client_t* client, zl_defer_cb cb)
{
    rtsp_request_t *req = rtsp_request_new(client, "OPTIONS", options_handler, cb);
    add_request(client, req);
}

void recv_handler(rtsp_client_t *client, const char *data, int size)
{
    const char* p = data;
    while (p < data + size) {
        if (client->pstate == RTSP_PARSE_INIT) {
            if (*p == '$') {
                sbuf_appendc(client->rcv_buf, *p);
                client->pstate = RTSP_PARSE_INTERLEAVED_HEADER;
            } else if ('A' <= *p && *p <= 'Z') {
                sbuf_appendc(client->rcv_buf, *p);
                client->pstate = RTSP_PARSE_HEADER;
            }
            ++p;
        } else if (client->pstate == RTSP_PARSE_INTERLEAVED_HEADER) {
            sbuf_appendc(client->rcv_buf, *p);
            assert(client->rcv_buf->size <= 4);
            if (client->rcv_buf->size == 4) {
                client->pstate = RTSP_PARSE_INTERLEAVED_CONTENT;
                client->expected_plen = ((unsigned char)client->rcv_buf->data[2] << 8)
                    + (unsigned char)client->rcv_buf->data[3];
            }
            ++p;
        } else if (client->pstate == RTSP_PARSE_INTERLEAVED_CONTENT) {
            if (p + client->expected_plen <= data + size) {
                sbuf_append2(client->rcv_buf, p, client->expected_plen);
                p += client->expected_plen;
                client->expected_plen = 0;

                assert(client->rcv_buf->size >= 4);
                rtp_packet_handler(client, client->rcv_buf->data + 4, client->rcv_buf->size - 4);
                sbuf_clear(client->rcv_buf);
                client->pstate = RTSP_PARSE_INIT;
            } else {
                const size_t len = data + size - p;
                sbuf_append2(client->rcv_buf, p, len);
                p += len;
                client->expected_plen -= len;
            }
        } else if (client->pstate == RTSP_PARSE_HEADER) {
            sbuf_appendc(client->rcv_buf, *p++);
            if (sbuf_ends_with(client->rcv_buf, "\r\n\r\n")) {
                char *q = strcasestr(client->rcv_buf->data, "Content-Length:");
                if (q) {
                    int len = 0;
                    sscanf(q + 15, " %d", &len);
                    if (p + len <= data + size) {
                        sbuf_append2(client->rcv_buf, p, len);
                        p += len;

                        request_reply_handler(client, client->rcv_buf->data, client->rcv_buf->size);
                        sbuf_clear(client->rcv_buf);
                        client->pstate = RTSP_PARSE_INIT;
                    } else {
                        sbuf_append2(client->rcv_buf, p, data + size - p);
                        client->expected_plen = p + len - (data + size);
                        client->pstate = RTSP_PARSE_CONTENT;
                    }
                } else {
                    request_reply_handler(client, client->rcv_buf->data, client->rcv_buf->size);
                    sbuf_clear(client->rcv_buf);
                    client->pstate = RTSP_PARSE_INIT;
                }
            }
        } else if (client->pstate == RTSP_PARSE_CONTENT) {
            if (p + client->expected_plen <= data + size) {
                sbuf_append2(client->rcv_buf, p, client->expected_plen);
                p += client->expected_plen;
                client->expected_plen = 0;

                request_reply_handler(client, client->rcv_buf->data, client->rcv_buf->size);
                sbuf_clear(client->rcv_buf);
                client->pstate = RTSP_PARSE_INIT;
            } else {
                const size_t len = data + size - p;
                sbuf_append2(client->rcv_buf, p, len);
                p += len;
                client->expected_plen -= len;
            }
        }
    }
}

void rtp_packet_handler(rtsp_client_t *client, const char *data, int size)
{
    if (client->packet_cb)
        client->packet_cb(data, size, client->udata);
}

void request_reply_handler(rtsp_client_t *client, const char *data, int size)
{
    LLOG(LL_TRACE, "'%s'", data);
    if (strstr(data, "RTSP/1.0") == data) {
        if (!list_empty(&client->request_list)) {
            rtsp_request_t *req = list_entry(client->request_list.next, rtsp_request_t, link);
            list_del(&req->link);
            if (req->cb)
                req->cb(client, req, data, size);
            rtsp_request_del(req);

            if (!list_empty(&client->request_list)) {
                req = list_entry(client->request_list.next, rtsp_request_t, link);
                buffer_request_to_send(client, req);
            }
        }
    } else {
        LLOG(LL_TRACE, "unhandled control data '%s'", data);
    }
}

static int parse_reply_status(const char *data)
{
    int status = 500;
    sscanf(data, "RTSP/1.0 %d", &status);
    return status;
}

void describe_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);
    if (status == 200) {
        const char *s = strstr(data, "\r\n\r\n");
        if (s)
            sbuf_strcpy(client->sdp, s + 4);
        else
            sbuf_clear(client->sdp);
    } else if (status == 401) {
        update_auth_info(client, data, size);
        LLOG(LL_ERROR, "rtsp describe reply error %d", status);
    } else {
        LLOG(LL_ERROR, "rtsp describe reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

void setup_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);
    if (status == 200) {
        const char *s = strcasestr(data, "Session:");
        if (s) {
            char *p = NULL;
            sscanf(s, "Session: %m[0-9a-fA-F_]", &p);
            if (p) {
                sbuf_strcpy(client->session, p);
                free(p);
            }
        }
    } else {
        LLOG(LL_ERROR, "rtsp setup reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

void play_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);
    if (status == 200) {
    } else {
        LLOG(LL_ERROR, "rtsp play reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

void pause_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);
    if (status == 200) {
    } else {
        LLOG(LL_ERROR, "rtsp play reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

void teardown_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);
    if (status == 200) {
    } else {
        LLOG(LL_ERROR, "rtsp play reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

void options_handler(rtsp_client_t *client, rtsp_request_t *req, const char *data, int size)
{
    int status = parse_reply_status(data);

    if (status == 200) {
    } else if (status == 401) {
        update_auth_info(client, data, size);
        LLOG(LL_ERROR, "rtsp OPTIONS reply error %d", status);
    } else {
        LLOG(LL_ERROR, "rtsp OPTIONS reply error %d", status);
    }
    if (req->ucb)
        req->ucb(client->loop, status, client->udata);
}

const char *get_auth_basic(rtsp_client_t *client)
{
    if (client->auth_basic_cache->size == 0) {
        sbuf_t *tmp = sbuf_new1(client->user->size + client->pwd->size + 2);
        sbuf_append(tmp, client->user);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, client->pwd);

        size_t olen = base64_encode(tmp->data, tmp->size, NULL, 0);
        sbuf_resize(client->auth_basic_cache, olen);
        base64_encode(tmp->data, tmp->size, client->auth_basic_cache->data, olen);
        sbuf_del(tmp);
    }
    return client->auth_basic_cache->data;
}

const char *get_auth_line(rtsp_client_t *client, const char* method)
{
    if (client->auth_type == RTSP_AUTH_BASIC) {
        if (client->user->size <= 0 || client->pwd->size <= 0)
            return "";
        
        if (client->auth_basic_line_cache->size == 0) {
            sbuf_append1(client->auth_basic_line_cache, "Authorization: Basic ");
            sbuf_append1(client->auth_basic_line_cache, get_auth_basic(client));
            sbuf_append1(client->auth_basic_line_cache, "\r\n");
        }
        return client->auth_basic_line_cache->data;
    } else if (client->auth_type == RTSP_AUTH_DIGEST) {
        uint8_t digest[17];
        MD5_CTX md5_ctx;
        sbuf_t *tmp = sbuf_new();
        // ha1 = md5(user ':' realm ':' pwd)
        sbuf_append(tmp, client->user);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, client->auth_realm);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, client->pwd);
        MD5Init(&md5_ctx);
        MD5Update(&md5_ctx, (uint8_t*)tmp->data, tmp->size);
        MD5Final(&md5_ctx, digest);
        sbuf_t *auth_ha1 = sbuf_newf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
                                     "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                                     digest[0], digest[1], digest[2], digest[3],
                                     digest[4], digest[5], digest[6], digest[7],
                                     digest[8], digest[9], digest[10], digest[11],
                                     digest[12], digest[13], digest[14], digest[15]);

        // ha3 = md5(method ':' uri)
        sbuf_clear(tmp);
        sbuf_append1(tmp, method);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, client->uri);
        MD5Init(&md5_ctx);
        MD5Update(&md5_ctx, (uint8_t*)tmp->data, tmp->size);
        MD5Final(&md5_ctx, digest);
        sbuf_t *auth_ha3 = sbuf_newf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
                                     "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                                     digest[0], digest[1], digest[2], digest[3],
                                     digest[4], digest[5], digest[6], digest[7],
                                     digest[8], digest[9], digest[10], digest[11],
                                     digest[12], digest[13], digest[14], digest[15]);


        // response = md5(ha1 ':' nonce ':' ha3)
        sbuf_clear(tmp);
        sbuf_append(tmp, auth_ha1);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, client->auth_nonce);
        sbuf_appendc(tmp, ':');
        sbuf_append(tmp, auth_ha3);
        MD5Init(&md5_ctx);
        MD5Update(&md5_ctx, (uint8_t*)tmp->data, tmp->size);
        MD5Final(&md5_ctx, digest);
        sbuf_t *auth_resp = sbuf_newf("%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
                                      "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
                                      digest[0], digest[1], digest[2], digest[3],
                                      digest[4], digest[5], digest[6], digest[7],
                                      digest[8], digest[9], digest[10], digest[11],
                                      digest[12], digest[13], digest[14], digest[15]);

        sbuf_clear(client->auth_digest_line_cache);
        sbuf_reserve(client->auth_digest_line_cache, 4096);
        client->auth_digest_line_cache->size = snprintf(client->auth_digest_line_cache->data,
                                                        client->auth_digest_line_cache->capacity - 1,
                                                        "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                                                        "uri=\"%s\", response=\"%s\"\r\n",
                                                        client->user->data, client->auth_realm->data,
                                                        client->auth_nonce->data, client->uri->data,
                                                        auth_resp->data);
        sbuf_del(tmp);
        sbuf_del(auth_ha3);
        sbuf_del(auth_resp);
        return client->auth_digest_line_cache->data;
    } else {
        assert(0);
        return "";
    }
}

rtsp_request_t *rtsp_request_new(rtsp_client_t *client, const char *method,
                                 rtsp_request_cb func, zl_defer_cb ucb)
{
    rtsp_request_t *req = malloc(sizeof(rtsp_request_t));
    req->client = client;
    req->method = method;
    req->uri = sbuf_clone(client->uri);
    req->cb = func;
    req->ucb = ucb;
    INIT_LIST_HEAD(&req->link);
    INIT_LIST_HEAD(&req->header_list);
    return req;
}

void rtsp_request_del(rtsp_request_t *req)
{
    sbuf_del(req->uri);
    free(req);
}

void add_request(rtsp_client_t *client, rtsp_request_t *req)
{
    int empty = list_empty(&client->request_list);
    req->timestamp = zl_timestamp();
    list_add_tail(&req->link, &client->request_list);
    if (empty)
        buffer_request_to_send(client, req);
}

void update_auth_info(rtsp_client_t *client, const char *data, size_t size)
{
    char *s = NULL, *p = NULL, *q = NULL;
    if ((s = strstr(data, "WWW-Authenticate")) != NULL) {
        client->auth_type = RTSP_AUTH_DIGEST;
        p = strstr(s, "realm=");
        if (p) {
            sscanf(p, "realm=\"%m[^\"]\"", &q);
            if (q) {
                sbuf_strcpy(client->auth_realm, q);
                free(q);
            }
        }
        p = strstr(s, "nonce=");
        if (p) {
            sscanf(p, "nonce=\"%m[^\"]\"", &q);
            if (q) {
                sbuf_strcpy(client->auth_nonce, q);
                free(q);
            }
        }
    }
}

void add_header(rtsp_request_t *req, const char *name, const char *value_format, ...)
{
    rtsp_header_t *hdr = malloc(sizeof(rtsp_header_t));
    hdr->name = name;
    va_list ap;
    va_start(ap, value_format);
    hdr->value = sbuf_newv(value_format, ap);
    va_end(ap);
    list_add_tail(&hdr->link, &req->header_list);
}

void buffer_request_to_send(rtsp_client_t* client, rtsp_request_t *req)
{
    sbuf_printf(client->snd_buf, "%s %s RTSP/1.0\r\n", req->method, req->uri->data);
    sbuf_appendf(client->snd_buf, "CSeq:%d\r\n", client->next_cseq++);
    sbuf_append1(client->snd_buf, get_auth_line(client, req->method));
    sbuf_appendf(client->snd_buf, "Session:%s\r\n", client->session->data);
    rtsp_header_t *hdr;
    list_for_each_entry(hdr, &req->header_list, link) {
        sbuf_append1(client->snd_buf, hdr->name);
        sbuf_appendc(client->snd_buf, ':');
        sbuf_append(client->snd_buf, hdr->value);
        sbuf_append1(client->snd_buf, "\r\n");
    }
    sbuf_append1(client->snd_buf, "\r\n");
    LLOG(LL_TRACE, "send '%s'", client->snd_buf->data);
    if (!(client->flag & RTSP_CLIENT_IN_EVENT_CB))
        update_poll_events(client);
}

void update_poll_events(rtsp_client_t *client)
{
    if (client->flag & RTSP_CLIENT_ERROR) {
        if (client->eevents) {
            client->eevents = 0;
            zl_fd_ctl(client->loop, EPOLL_CTL_DEL, client->fd, 0, NULL, client);
        }
        return;
    }
    uint32_t pevents = EPOLLIN;
    if (!sbuf_empty(client->snd_buf))
        pevents |= EPOLLOUT;
    if (pevents != client->eevents) {
        client->eevents = pevents;
        if (pevents)
            zl_fd_ctl(client->loop, EPOLL_CTL_MOD, client->fd, pevents, client_handler, client);
        else
            zl_fd_ctl(client->loop, EPOLL_CTL_DEL, client->fd, 0, NULL, client);
    }
}

void error_handler(rtsp_client_t *client, int err)
{
    if (client->connect_cb) {
        zl_defer_cb cb = client->connect_cb;
        client->connect_cb = NULL;
        cb(client->loop, err, client->udata);
    }
    rtsp_request_t *req;
    while (!list_empty(&client->request_list)) {
        req = list_entry(client->request_list.next, rtsp_request_t, link);
        list_del_init(&req->link);
        if (req->ucb)
            req->ucb(client->loop, err, client->udata);
        rtsp_request_del(req);
    }
}

void rtsp_client_cron(zl_loop_t *loop)
{
    long long now = zl_timestamp();
    rtsp_client_t *client, *tmp;
    list_for_each_entry_safe(client, tmp, &timeout_check_list, timeout_link) {
        rtsp_client_timeout_check(client, now);
    }
}

long long rtsp_client_get_timestamp(rtsp_client_t *client)
{
    if (client->connect_cb)
        return client->connect_timestamp;
    if (list_empty(&client->request_list))
        return zl_timestamp();
    rtsp_request_t *req = list_entry(client->request_list.next, rtsp_request_t, link);
    return req->timestamp;
}

void rtsp_client_timeout_check(rtsp_client_t *client, long long now)
{
    long long timestamp = rtsp_client_get_timestamp(client);
    if (timestamp + RTSP_CLIENT_TIMEOUT_MSECS < now)
        error_handler(client, -ETIMEDOUT);
}
