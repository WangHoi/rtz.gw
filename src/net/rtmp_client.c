#include "rtmp_client.h"
#include "event_loop.h"
#include "sbuf.h"
#include "net_util.h"
#include "log.h"
#include "base64.h"
#include "md5.h"
#include "list.h"
#include "pack_util.h"
#include "rtmp_types.h"
#include "rtp_types.h"
#include "h26x.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

enum {
    RTMP_CLIENT_URI_SIZE = 4096,
    RTMP_CLIENT_IP_SIZE = 64,
    RTMP_CLIENT_RCV_BUF_SIZE = 65536,
    RTMP_CLIENT_SND_BUF_SIZE = 65536,
    RTMP_CLIENT_DEFAULT_PORT = 1935,
    RTMP_CLIENT_TIMEOUT_MSECS = 3000,
};

enum rtmp_client_flag {
    RTMP_CLIENT_IN_EVENT_CB = 1,
    RTMP_CLIENT_ERROR = 2,
};

typedef enum rtmp_parse_state_t {
    RTMP_PARSE_INIT,
    RTMP_PARSE_CHUNK_HEADER,
    RTMP_PARSE_CHUNK_BODY,
    NUM_RTMP_PARSE_STATES,
} rtmp_parse_state_t;

typedef enum rtmp_handshake_state_t {
    RTMP_HS_INIT,
    RTMP_HS_WAIT_S1,
    RTMP_HS_WAIT_S2,
    RTMP_HS_DONE,
} rtmp_handshake_state_t;

struct rtmp_client_t {
    zl_loop_t *loop;
    int flag;

    sbuf_t *uri;
    sbuf_t *ip;
    sbuf_t *app;
    sbuf_t *stream;
    unsigned short port;

    rtmp_handshake_state_t hstate;
    rtmp_parse_state_t pstate;
    rtmp_chunk_t last_chunks[RTMP_MAX_CHUNK_STREAMS];
    unsigned next_tx_id;
    rtmp_chunk_t cur_chunk;
    int recv_body_size_limit;
    char header[RTMP_MAX_CHUNK_HEADER_SIZE];
    unsigned char expected_hlen;

    void *udata;
    long long connect_timestamp;
    zl_defer_cb connect_cb;
    rtmp_packet_cb video_cb;
    rtmp_packet_cb audio_cb;
    struct list_head request_list;

    sbuf_t *sps;
    sbuf_t *pps;
    int vcodec_changed;

    int fd;
    uint32_t eevents;
    sbuf_t *rcv_buf;
    sbuf_t *snd_buf;
    int sent_size;

    struct list_head timeout_link;
};

typedef struct rtmp_request_t {
    rtmp_client_t *client;
    long long timestamp;
    const char *method;
    unsigned char channel;
    unsigned tx_id;
    sbuf_t *buf;
    //rtsp_request_cb cb;
    zl_defer_cb ucb;
    struct list_head link;
} rtmp_request_t;

static LIST_HEAD(timeout_check_list);

static rtmp_request_t *rtmp_request_new(rtmp_client_t *client, const char *method,
                                        unsigned channel, zl_defer_cb ucb);
static void rtmp_request_del(rtmp_request_t *req);
static void connect_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);
static void send_c01(rtmp_client_t *client);
static void send_c2(rtmp_client_t *client, const char *s1);
static void client_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);
static void handshake_handler(rtmp_client_t *client, int fd, uint32_t events);
static void session_handler(rtmp_client_t *client, int fd, uint32_t events);
static void error_handler(rtmp_client_t *client, int err);
static void recv_handler(rtmp_client_t *client, const char *data, int size);
static void chunk_handler(rtmp_client_t *client);
static void notify_handler(rtmp_client_t *client, const char *cmd,
                           const char *data, int size);
static void event_handler(rtmp_client_t *client, rtmp_event_type_t type,
                          const char *data, int size);
static void command_handler(rtmp_client_t *client, unsigned chan, const char *cmd,
                            unsigned tx_id, const char *data, int size);
static void update_poll_events(rtmp_client_t *client);
static void send_connect(rtmp_client_t *client, zl_defer_cb ucb);
static void send_create_stream(rtmp_client_t *client, zl_defer_cb ucb);
static void send_release_stream(rtmp_client_t *client, zl_defer_cb ucb);
static void send_fcpublish(rtmp_client_t *client, zl_defer_cb ucb);
static void send_publish(rtmp_client_t *client, zl_defer_cb ucb);
static void send_play(rtmp_client_t *client, zl_defer_cb ucb);
static void send_video(rtmp_client_t *client, uint32_t timestamp, const void *data, int size);
static int is_publish_status(int64_t status);
static void finish_requests(rtmp_client_t *client, unsigned tx_id, int64_t status);
static rtmp_status_t get_status(const char *data, size_t size);

rtmp_client_t *rtmp_client_new(zl_loop_t *loop)
{
    int i;
    rtmp_client_t *client = malloc(sizeof(rtmp_client_t));
    memset(client, 0, sizeof(rtmp_client_t));
    client->loop = loop;
    client->udata = client;
    client->uri = sbuf_new1(RTMP_CLIENT_URI_SIZE);
    client->ip = sbuf_new1(RTMP_CLIENT_IP_SIZE);
    client->app = sbuf_new();
    client->stream = sbuf_new();
    client->rcv_buf = sbuf_new(RTMP_CLIENT_RCV_BUF_SIZE);
    client->snd_buf = sbuf_new(RTMP_CLIENT_SND_BUF_SIZE);
    client->hstate = RTMP_HS_INIT;
    client->pstate = RTMP_PARSE_INIT;
    client->recv_body_size_limit = RTMP_DEFAULT_CHUNK_BODY_SIZE;
    client->next_tx_id = 1;
    client->sps = sbuf_new();
    client->pps = sbuf_new();
    client->vcodec_changed = 1;
    INIT_LIST_HEAD(&client->request_list);
    list_add_tail(&client->timeout_link, &timeout_check_list);
    return client;
}

void rtmp_client_set_userdata(rtmp_client_t *client, void *udata)
{
    client->udata = udata;
}

void rtmp_client_del(rtmp_client_t *client)
{
    sbuf_del(client->uri);
    sbuf_del(client->ip);
    sbuf_del(client->app);
    sbuf_del(client->stream);
    sbuf_del(client->sps);
    sbuf_del(client->pps);
    list_del(&client->timeout_link);
    free(client);
}

void rtmp_client_set_uri(rtmp_client_t *client, const char *uri)
{
    sbuf_strcpy(client->uri, uri);
    char *ip = NULL;
    int n;
    n = sscanf(client->uri->data, "rtmp://%m[0-9.]:%hu", &ip, &client->port);
    if (n >= 1)
        sbuf_strcpy(client->ip, ip);
    if (n < 2)
        client->port = RTMP_CLIENT_DEFAULT_PORT;
    free(ip);
    char *p = strchr(client->uri->data + 7, '/');
    if (p) {
        char *q = strchr(p + 1, '/');
        if (q) {
            sbuf_strncpy(client->app, p + 1, q - (p + 1));
            sbuf_strcpy(client->stream, q + 1);
        } else {
            sbuf_strcpy(client->app, p + 1);
        }
    }
    LLOG(LL_TRACE, "ip=%s port=%hu app=%s stream=%s", client->ip->data,
         client->port, client->app->data, client->stream->data);
}

void rtmp_client_connect(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
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
    client->eevents = EPOLLOUT;
    ret = zl_fd_ctl(client->loop, EPOLL_CTL_ADD, client->fd, client->eevents, &connect_handler, client);
    LLOG(LL_TRACE, "ret=%d", ret);
}

void rtmp_client_aconnect(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_connect(client, func);
}
void rtmp_client_create_stream(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_create_stream(client, func);
}
void rtmp_client_play(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_play(client, func);
}
void rtmp_client_release_stream(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_release_stream(client, func);

}
void rtmp_client_fcpublish(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_fcpublish(client, func);
}
void rtmp_client_publish(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_publish(client, func);
}

void rtmp_client_abort(rtmp_client_t *client)
{
    error_handler(client, -ECANCELED);
    if (client->fd != -1) {
        zl_fd_ctl(client->loop, EPOLL_CTL_DEL, client->fd, 0, NULL, NULL);
        close(client->fd);
        client->fd = -1;
    }
}

void rtmp_client_set_video_packet_cb(rtmp_client_t *client, rtmp_packet_cb func)
{
    client->video_cb = func;
}

void rtmp_client_set_audio_packet_cb(rtmp_client_t *client, rtmp_packet_cb func)
{
    client->audio_cb = func;
}

void rtmp_client_send_video(rtmp_client_t *client, uint32_t timestamp, const char *data, int size)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        return;
    }

    send_video(client, timestamp, data, size);
}

void rtmp_client_cron(zl_loop_t *loop)
{

}

void connect_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    if (!(events & (EPOLLOUT | EPOLLHUP | EPOLLERR)))
        return;
    rtmp_client_t* client = udata;
    client->flag |= RTMP_CLIENT_IN_EVENT_CB;
    int err = get_socket_error(fd);
    if (err == 0) {
        send_c01(client);
        client->hstate = RTMP_HS_WAIT_S1;

        uint32_t pevents = EPOLLIN | EPOLLOUT;
        //if (pevents != client->eevents) {
            client->eevents = pevents;
            zl_fd_ctl(loop, EPOLL_CTL_MOD, fd, pevents, client_handler, client);
        //}
    } else {
        client->flag |= RTMP_CLIENT_ERROR;
        client->eevents = 0;
        zl_fd_ctl(loop, EPOLL_CTL_DEL, fd, 0, NULL, client);
    }
    if (client->flag & RTMP_CLIENT_ERROR)
        error_handler(client, -EINVAL);
    client->flag &= ~RTMP_CLIENT_IN_EVENT_CB;
}

void send_c01(rtmp_client_t *client)
{
    sbuf_appendc(client->snd_buf, RTMP_HANDSHAKE_C0);
    sbuf_makeroom(client->snd_buf, RTMP_HANDSHAKE_C1_SIZE);
    char *tail = sbuf_tail(client->snd_buf);
    uint32_t now = (uint32_t)(zl_time() / 1000);
    pack_be32(tail, now);
    pack_be32(tail + 4, 0);
    memset(tail + 8, 0, RTMP_HANDSHAKE_C1_SIZE - 8);
    tail[RTMP_HANDSHAKE_C1_SIZE] = 0;
    client->snd_buf->size += RTMP_HANDSHAKE_C1_SIZE;
}

void client_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    rtmp_client_t *client = udata;
    client->flag |= RTMP_CLIENT_IN_EVENT_CB;
    if (client->hstate != RTMP_HS_DONE)
        handshake_handler(client, fd, events);
    else
        session_handler(client, fd, events);
    update_poll_events(client);
    if (client->flag & RTMP_CLIENT_ERROR)
        error_handler(client, -EINVAL);
    client->flag &= ~RTMP_CLIENT_IN_EVENT_CB;
}

void handshake_handler(rtmp_client_t *client, int fd, uint32_t events)
{
    int n;
    if (events & (EPOLLIN | EPOLLERR | EPOLLHUP)) {
        if (client->hstate == RTMP_HS_WAIT_S1) {
            n = RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE - client->rcv_buf->size;
            sbuf_makeroom(client->rcv_buf, n);
again_s1:
            n = read(fd, sbuf_tail(client->rcv_buf), n);
            if (n == -1) {
                if (errno == EINTR) {
                    goto again_s1;
                } else if (errno == EAGAIN) {
                    n = 0;
                } else {
                    LLOG(LL_ERROR, "read error %s", strerror(errno));
                    client->flag |= RTMP_CLIENT_ERROR;
                }
            }
            client->rcv_buf->size += n;
            client->rcv_buf->data[client->rcv_buf->size] = 0;

            if (client->rcv_buf->size == RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE) {
                send_c2(client, &client->rcv_buf->data[1]);
                sbuf_clear(client->rcv_buf);
                client->hstate = RTMP_HS_WAIT_S2;
            }
        } else if (client->hstate == RTMP_HS_WAIT_S2) {
            n = RTMP_HANDSHAKE_S2_SIZE - client->rcv_buf->size;
            sbuf_makeroom(client->rcv_buf, n);
again_s2:
            n = read(fd, sbuf_tail(client->rcv_buf), n);
            if (n == -1) {
                if (errno == EINTR)
                    goto again_s2;
                else
                    client->flag |= RTMP_CLIENT_ERROR;
            }
            client->rcv_buf->size += n;
            client->rcv_buf->data[client->rcv_buf->size] = 0;

            if (client->rcv_buf->size == RTMP_HANDSHAKE_S2_SIZE) {
                client->hstate = RTMP_HS_DONE;
                sbuf_clear(client->rcv_buf);
                if (!list_empty(&client->request_list)) {
                    rtmp_request_t *req;
                    list_for_each_entry(req, &client->request_list, link) {
                        rtmp_write_chunk(client->snd_buf, req->channel, 0, RTMP_MESSAGE_AMF0_CMD, 0,
                                         req->buf->data, req->buf->size);
                    }
                }
                if (client->connect_cb) {
                    zl_defer_cb cb = client->connect_cb;
                    client->connect_cb = NULL;
                    cb(client->loop, 0, client->udata);
                }
            }
        }
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
                    client->flag |= RTMP_CLIENT_ERROR;
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
}

void session_handler(rtmp_client_t *client, int fd, uint32_t events)
{
    if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
        char *buf = malloc(RTMP_CLIENT_RCV_BUF_SIZE);
        int n = RTMP_CLIENT_RCV_BUF_SIZE;
read_again:
        n = read(fd, buf, n);
        if (n == -1) {
            if (errno == EINTR) {
                goto read_again;
            } else {
                LLOG(LL_TRACE, "client %d read err: %s", fd, strerror(errno));
                client->flag |= RTMP_CLIENT_ERROR;
            }
        } else if (n == 0) {
            LLOG(LL_TRACE, "client %d eof", fd);
            client->flag |= RTMP_CLIENT_ERROR;
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
                    client->flag |= RTMP_CLIENT_ERROR;
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
}

void send_c2(rtmp_client_t *client, const char *s1)
{
    sbuf_append2(client->snd_buf, s1, RTMP_HANDSHAKE_C2_SIZE);
}

void error_handler(rtmp_client_t *client, int err)
{
    if (client->connect_cb) {
        zl_defer_cb cb = client->connect_cb;
        client->connect_cb = NULL;
        cb(client->loop, err, client->udata);
    }
    /*
    rtsp_request_t *req;
    while (!list_empty(&client->request_list)) {
        req = list_entry(client->request_list.next, rtsp_request_t, link);
        list_del_init(&req->link);
        if (req->ucb)
            req->ucb(client->loop, err, client->udata);
        rtsp_request_del(req);
    }
    */
}

void recv_handler(rtmp_client_t *client, const char *data, int size)
{
    const char* p = data;
    while (p < data + size) {
        if (client->pstate == RTMP_PARSE_INIT) {
            client->header[0] = *p++;
            client->cur_chunk.chunk_channel = rtmp_chunk_channel(client->header[0]);
            client->expected_hlen = rtmp_chunk_header_len(client->header) - 1;

            if (client->expected_hlen > 0) {
                client->pstate = RTMP_PARSE_CHUNK_HEADER;
            } else {
                rtmp_chunk_t *lc = &client->last_chunks[client->cur_chunk.chunk_channel];
                client->cur_chunk.body_size = lc->body_size;
                client->cur_chunk.type_id = lc->type_id;
                client->cur_chunk.timestamp = lc->timestamp;
                client->cur_chunk.timestamp_delta = lc->timestamp_delta;
                client->pstate = RTMP_PARSE_CHUNK_BODY;
            }
        } else if (client->pstate == RTMP_PARSE_CHUNK_HEADER) {
            unsigned char len = client->expected_hlen;
            if (len > data + size - p)
                len = data + size - p;
            memcpy(client->header + rtmp_chunk_header_len(client->header) - client->expected_hlen,
                   p, len);
            p += len;
            client->expected_hlen -= len;
            if (client->expected_hlen == 0) {
                unsigned fmt = rtmp_chunk_header_fmt(client->header);
                if (fmt == 0) {
                    client->cur_chunk.timestamp = unpack_be24(&client->header[1]);
                    client->cur_chunk.body_size = unpack_be24(&client->header[4]);
                    client->cur_chunk.type_id = (unsigned char)client->header[7];
                    client->cur_chunk.msg_stream_id = unpack_le32 (&client->header[8]);
                    memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                           &client->cur_chunk, sizeof(rtmp_chunk_t));
                } else if (fmt == 1) {
                    client->cur_chunk.timestamp_delta = unpack_be24(&client->header[1]);
                    client->cur_chunk.body_size = unpack_be24(&client->header[4]);
                    client->cur_chunk.type_id = (unsigned char)client->header[7];
                    client->cur_chunk.timestamp = client->last_chunks[client->cur_chunk.chunk_channel].timestamp
                        + client->cur_chunk.timestamp_delta;
                    memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                           &client->cur_chunk, sizeof(rtmp_chunk_t));
                } else if (fmt == 2) {
                    rtmp_chunk_t *lc = &client->last_chunks[client->cur_chunk.chunk_channel];
                    client->cur_chunk.timestamp_delta = unpack_be24(&client->header[1]);
                    client->cur_chunk.body_size = lc->body_size;
                    client->cur_chunk.type_id = lc->type_id;
                    client->cur_chunk.timestamp = lc->timestamp + client->cur_chunk.timestamp_delta;
                    memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                           &client->cur_chunk, sizeof(rtmp_chunk_t));
                }
                //log_info ("body_size={}",  _chunk_header.body_size);
                sbuf_clear(client->rcv_buf);
                client->pstate = RTMP_PARSE_CHUNK_BODY;
            }
        } else if (client->pstate == RTMP_PARSE_CHUNK_BODY) {
            int n = client->cur_chunk.body_size - client->rcv_buf->size;
            if (n > data + size - p)
                n = data + size - p;
            int m = client->recv_body_size_limit - (client->rcv_buf->size % client->recv_body_size_limit);
            if (n > m)
                n = m;
            sbuf_append2(client->rcv_buf, p, n);
            p += n;
            //log_info ("{} {} {}", _cur_chunk_size, _chunk_header.body_size, _last_chunk_headers[_chunk_header.chunk_channel].body_size);
            if (client->rcv_buf->size % client->recv_body_size_limit == 0) {
                //log_info ("chunk size {} limit reached, next_p={:02x}", _cur_chunk_size, p[0]);
                client->pstate = RTMP_PARSE_INIT;
            }
            if (client->rcv_buf->size == client->cur_chunk.body_size) {
                //log_info ("buffer_size={} hdr_size={} body_size={}", _buffer.size (), _chunk_header.header_size, _chunk_header.body_size);
                chunk_handler(client);
                sbuf_clear(client->rcv_buf);
                client->expected_hlen = 0;
                client->pstate = RTMP_PARSE_INIT;
            }
        }
    }
}

void chunk_handler(rtmp_client_t *client)
{
    rtmp_chunk_t *hdr = &client->cur_chunk;
    char *data = client->rcv_buf->data;
    int size = client->rcv_buf->size;
    sbuf_t *cmd_name = sbuf_new();
    if (hdr->type_id == RTMP_MESSAGE_SET_CHUNK_SIZE) {
        if (hdr->body_size == 4) {
            uint32_t chunk_size = unpack_be32(data) & 0x7fffffff;
            LLOG(LL_TRACE, "SetChunkSize %d", (int)chunk_size);
            client->recv_body_size_limit = chunk_size;
        } else {
            LLOG(LL_ERROR, "invalid SetChunkSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_ABORT) {
        LLOG(LL_TRACE, "Abort Message");
    } else if (hdr->type_id == RTMP_MESSAGE_ACK) {
        if (hdr->body_size == 4) {
            uint32_t seq = unpack_be32(data);
            LLOG(LL_TRACE, "Ack seq=%d", (int)seq);
        } else {
            LLOG(LL_ERROR, "invalid Ack body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_USER_CONTROL) {
        if (hdr->body_size >= 2) {
            rtmp_event_type_t etype = unpack_be16(data);
            char *edata = data + 2;
            uint32_t esize = hdr->body_size - 2;
            event_handler(client, etype, edata, esize);
            LLOG(LL_TRACE, "ping event_type=%d event_size=%d", (int)etype, (int)esize);
        } else {
            LLOG(LL_ERROR, "UserControl invalid body_size=%d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_WINDOW_ACK_SIZE) {
        if (hdr->body_size == 4) {
            uint32_t size = unpack_be32(data);
            LLOG(LL_TRACE, "window ack size=%d", (int)size);
            //_wnd_ack_size = size;
            //SendWindowAckSize ();
        } else {
            LLOG(LL_ERROR, "invalid WindowAckSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_SET_PEER_BANDWIDTH) {
        if (hdr->body_size == 5) {
            uint32_t size = unpack_be32(data);
            unsigned char limit_type = (unsigned char)data[4];
            LLOG(LL_TRACE, "SetPeerBandwidth size=%d limit_type=%hhu", (int)size, limit_type);
        } else {
            LLOG(LL_ERROR, "invalid WindowAckSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AUDIO) {
        //if (_listener != nullptr) {
            //_listener->OnRTMPAudioData (_chunk_header.timestamp, 40, data, size);
        //}
        if (client->audio_cb)
            client->audio_cb(hdr->timestamp, data, size, client->udata);
    } else if (hdr->type_id == RTMP_MESSAGE_VIDEO) {
        //LLOG(LL_TRACE, "video size=%d data=%02hhx%02hhx%02hhx%02hhx", (int)size, data[0], data[1], data[2], data[3]);
        if (size > 5) {
            if ((data[0] & 0xf) == 7) { // avc codec
                if (data[1] == 0) {
                    //_listener->OnRTMPAVCHeader (data + 5, size - 5);
                } else {
                    char *p = data + 5;
                    int psize = size - 5;
                    while (psize > 4) {
                        uint32_t nalu_size = unpack_be32(p);
                        if (4 + nalu_size <= psize) {
                            unsigned nalu_type = p[4] & 0x1f;
                            //LLOG(LL_TRACE, "nalu type=%hhu size=%d", nalu_type, nalu_size);
                            if (nalu_type == 5 || nalu_type == 1) {
                                //log_info ("ts={}", _chunk_header.timestamp);
                                //_listener->OnRTMPVideoData (hdr->timestamp, 40, p, nalu_size + 4);
                                if (client->video_cb)
                                    client->video_cb(hdr->timestamp, data, size, client->udata);
                            }
                            p += 4 + nalu_size;
                            psize -= 4 + nalu_size;
                        } else {
                            break;
                        }
                    }
                }
            } else {
                LLOG(LL_ERROR, "unsupported codec id=%hhu", ((unsigned char)data[0] & 0xf));
            }
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_NOTIFY) {
        LLOG(LL_TRACE, "AMF0 Data Message size=%d", (int)hdr->body_size);
        int n = amf0_read_string(data, hdr->body_size, cmd_name);
        notify_handler(client, cmd_name->data, data + n, hdr->body_size - n);
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_CMD) {
        sbuf_t *cmd_name = sbuf_new();
        double tx_id;
        int n = amf0_read_string(data, hdr->body_size, cmd_name);
        //log_info ("n={} {} {} {}", n, data[0], data[1], data[2]);
        n += amf0_read_number(data + n, hdr->body_size - n, &tx_id);
        command_handler(client, hdr->chunk_channel, cmd_name->data,
            (unsigned)lroundl(tx_id), data + n, hdr->body_size - n);
    } else if (hdr->type_id == RTMP_MESSAGE_AMF3_CMD) {
        sbuf_t *cmd_name = sbuf_new();
        double tx_id;
        if (data[1] == AMF0_TYPE_STRING) {
            int n = amf0_read_string (data + 1, hdr->body_size, cmd_name);
            //log_info ("n1={}", n);
            ++n; // skip one byte
            n += amf0_read_number (data + n, hdr->body_size - n, &tx_id);
            command_handler(client, hdr->chunk_channel, cmd_name->data,
                (unsigned)lroundl(tx_id), data + n, hdr->body_size - n);
        } else {
            LLOG(LL_WARN, "ignore %hhu %hhu amf3 cmd", data[0], data[1]);
        }
    } else {
        LLOG(LL_WARN, "unhandled ChunkTypeID %hhu", hdr->type_id);
    }
    sbuf_del(cmd_name);
}

void event_handler(rtmp_client_t *client, rtmp_event_type_t type,
                   const char *data, int size)
{
    if (type == RTMP_EVENT_PING_REQUEST) {
        rtmp_write_pong(client->snd_buf, data, size);
    } else if (type == RTMP_EVENT_SET_BUFFER_LENGTH) {
        uint32_t stream_id = unpack_be32(data);
        uint32_t delay = unpack_be32(data + 4);
        //SendSetBufferLength (stream_id, 0);
    }
}

void notify_handler(rtmp_client_t *client, const char *cmd,
                    const char *data, int size)
{
    LLOG(LL_TRACE, "notify '%s'", cmd);
    if (!strcmp(cmd, "|RtmpSampleAccess")) {
    } else if (!strcmp(cmd, "onMetaData")) {
    } else {

    }
}

int is_publish_status(int64_t status)
{
    return (status >= RTMP_NETSTREAM_PUBLISH_START
            && status <= RTMP_NETSTREAM_PUBLISH_IDLE);
}

void finish_requests(rtmp_client_t *client, unsigned tx_id, int64_t status)
{
    while (!list_empty(&client->request_list)) {
        rtmp_request_t *req = list_entry(client->request_list.next, rtmp_request_t, link);
        if (is_publish_status(status) && !strcmp(req->method, "publish")) {
            list_del_init(&req->link);
            if (req->ucb)
                req->ucb(client->loop, status, client->udata);
            rtmp_request_del(req);
            break;
        }

        if (req->tx_id > tx_id)
            break;
        list_del_init(&req->link);
        if (req->ucb)
            req->ucb(client->loop, (req->tx_id < tx_id) ? RTMP_SKIP_RESPONSE : status, client->udata);
        rtmp_request_del(req);
    }
}

void command_handler(rtmp_client_t *client, unsigned channel, const char *cmd,
                     unsigned tx_id, const char *data, int size)
{
    const char *p = data;
    int64_t status;
    if (!strcmp(cmd, "onStatus")) {
        p += amf0_skip(p, data + size - p);
        status = get_status(p, data + size - p);
        LLOG(LL_TRACE, "onStatus: %ld", status);

        finish_requests(client, tx_id, status);
    } else if (!strcmp(cmd, "_result")) {
        p += amf0_skip(p, data + size - p); // skip object
        status = get_status(p, data + size - p);
        LLOG(LL_TRACE, "_result: %ld", status);

        finish_requests(client, tx_id, status);
    } else {
        LLOG(LL_WARN, "ignore cmd '%s' tx_id=%u", cmd, tx_id);
    }
}

void update_poll_events(rtmp_client_t *client)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
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
        zl_fd_ctl(client->loop, EPOLL_CTL_MOD, client->fd, pevents,
                  client_handler, client);
    }
}

void add_request(rtmp_client_t *client, rtmp_request_t *req)
{
    req->timestamp = zl_timestamp();
    list_add_tail(&req->link, &client->request_list);
    if (client->hstate != RTMP_HS_DONE)
        return;
    rtmp_write_chunk(client->snd_buf, req->channel, 0, RTMP_MESSAGE_AMF0_CMD, 0,
                     req->buf->data, req->buf->size);
    if (!(client->flag & RTMP_CLIENT_IN_EVENT_CB))
        update_poll_events(client);
}

rtmp_request_t *rtmp_request_new(rtmp_client_t *client, const char *method,
                                 unsigned channel, zl_defer_cb ucb)
{
    assert(channel < RTMP_MAX_CHUNK_STREAMS);
    rtmp_request_t *req = malloc(sizeof(rtmp_request_t));
    req->method = method;
    req->channel = channel;
    req->tx_id = client->next_tx_id++;
    req->buf = sbuf_new();
    req->ucb = ucb;
    INIT_LIST_HEAD(&req->link);
    return req;
}

void rtmp_request_del(rtmp_request_t *req)
{
    sbuf_del(req->buf);
    free(req);
}

/**
 * connect(txID, {app, tcUrl});
 */
void send_connect(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "connect", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "connect");
    p += amf0_write_number(p, pend - p, req->tx_id);

    p += amf0_write_object_start(p, pend - p);
    p += amf0_write_field_name(p, pend - p, "app");
    p += amf0_write_string(p, pend - p, client->app->data);
    //p += amf0_write_field_name(p, pend - p, "flashVer");
    //p += amf0_write_string(p, pend - p, "WIN 31,0,0,122");
    //p += amf0_write_field_name(p, pend - p, "swfUrl");
    //p += amf0_write_string(p, pend - p, "http://127.0.0.1/Main.swf");
    p += amf0_write_field_name(p, pend - p, "tcUrl");
    sbuf_t *tc_url = sbuf_newf("rtmp://%s:%hu/%s", client->ip->data, client->port, client->app->data);
    p += amf0_write_string(p, pend - p, tc_url->data);
    sbuf_del(tc_url);
    //p += amf0_write_field_name(p, pend - p, "fPad");
    //p += amf0_write_boolean(p, pend - p, 0);
    p += amf0_write_field_name(p, pend - p, "capabilities");
    p += amf0_write_number(p, pend - p, 239);
    p += amf0_write_field_name(p, pend - p, "audioCodecs");
    p += amf0_write_number(p, pend - p, 3575);
    p += amf0_write_field_name(p, pend - p, "videoCodecs");
    p += amf0_write_number(p, pend - p, 252);
    p += amf0_write_field_name(p, pend - p, "videoFunction");
    p += amf0_write_number (p, pend - p, 1);
    //p += amf0_write_field_name(p, pend - p, "pageUrl");
    //p += amf0_write_string(p, pend - p, "http://127.0.0.1/");
    p += amf0_write_field_name(p, pend - p, "objectEncoding");
    p += amf0_write_number(p, pend - p, 0);
    p += amf0_write_object_end(p, pend - p);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * createStream(txID, null);
 */
void send_create_stream(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "createStream", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "createStream");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

void send_play(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "play", RTMP_SOURCE_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "play");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * releaseStream(txID, null, streamName);
 */
void send_release_stream(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "releaseStream", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "releaseStream");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * FCPublish(txID, null, streamName);
 */
void send_fcpublish(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "FCPublish", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, req->method);
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * publish(txID, null, streamName, appName);
 */
void send_publish(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "publish", RTMP_SOURCE_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, req->method);
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    p += amf0_write_string(p, pend - p, client->app->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

void send_video(rtmp_client_t *client, uint32_t timestamp, const void *data, int size)
{
    const h264_nalu_header_t *hdr = data;
    sbuf_t *buf = sbuf_new1(size + 16);
    if (hdr->type == H264_NALU_SPS) {
        sbuf_strncpy(client->sps, data, size);
    } else if (hdr->type == H264_NALU_PPS) {
        sbuf_strncpy(client->pps, data, size);
    } else if (hdr->type == H264_NALU_IFRAME) {
        if (client->vcodec_changed && client->sps->size >= 4 && !sbuf_empty(client->pps)) {
            client->vcodec_changed = 0;

            sbuf_appendc(buf, 0x17);
            sbuf_appendc(buf, 0);   // AVC sequence header
            sbuf_appendc(buf, 0);
            sbuf_appendc(buf, 0);
            sbuf_appendc(buf, 0);
            /*AVCDecoderConfigurationRecord*/
            sbuf_appendc(buf, 0x01);
            sbuf_append2(buf, client->sps->data + 1, 3);
            sbuf_appendc(buf, 0xff);
            /*sps*/
            sbuf_appendc(buf, 0xe1);
            sbuf_appendc(buf, (client->sps->size >> 8) & 0xff);
            sbuf_appendc(buf, client->sps->size & 0xff);
            sbuf_append(buf, client->sps);
            /*pps*/
            sbuf_appendc(buf, 0x01);
            sbuf_appendc(buf, (client->pps->size >> 8) & 0xff);
            sbuf_appendc(buf, client->pps->size & 0xff);
            sbuf_append(buf, client->pps);

            rtmp_write_chunk(client->snd_buf, RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                             timestamp, buf->data, buf->size);

            sbuf_clear(buf);
            LLOG(LL_TRACE, "send AVC sequence header");
        }
        sbuf_appendc(buf, 0x17);
        sbuf_appendc(buf, 1);       // AVC NALU
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_resize(buf, buf->size + 4);
        pack_be32(sbuf_tail(buf) - 4, size);
        sbuf_append2(buf, data, size);

        rtmp_write_chunk(client->snd_buf, RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                         timestamp, buf->data, buf->size);
        if (!(client->flag & RTMP_CLIENT_IN_EVENT_CB))
            update_poll_events(client);
        LLOG(LL_TRACE, "send AVC NALU KeyFrame timestamp=%u size=%d", timestamp, buf->size);

    } else {
        sbuf_appendc(buf, 0x27);
        sbuf_appendc(buf, 1);       // AVC NALU
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_resize(buf, buf->size + 4);
        pack_be32(sbuf_tail(buf) - 4, size);
        sbuf_append2(buf, data, size);

        rtmp_write_chunk(client->snd_buf, RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                         timestamp, buf->data, buf->size);
        if (!(client->flag & RTMP_CLIENT_IN_EVENT_CB))
            update_poll_events(client);
        //LLOG(LL_TRACE, "send AVC NALU PFrame timestamp=%u size=%d", timestamp, buf->size);
    }
    sbuf_del(buf);
}

rtmp_status_t get_status(const char *data, size_t size)
{
    if (size <= 0)
        return RTMP_INVALID_STATUS;
    sbuf_t *field_name = sbuf_new();
    sbuf_t *code = sbuf_new();
    const char *p = data;
    char type = *p++;
    rtmp_status_t status = RTMP_INVALID_STATUS;
    double n = 1.0;
    if (type == AMF0_TYPE_OBJECT) {
        while (p < data + size) {
            p += amf0_read_fieldname(p, data + size - p, field_name);
            if (!strcmp(field_name->data, "code")) {
                p += amf0_read_string(p, data + size - p, code);
                break;
            } else {
                p += amf0_skip(p, data + size - p);
            }
        }
        if (!strcmp(code->data, "NetStream.Play.Start"))
            status = RTMP_NETSTREAM_PLAY_START;
        else if (!strcmp(code->data, "NetStream.Play.Stop"))
            status = RTMP_NETSTREAM_PLAY_STOP;
        else if (!strcmp(code->data, "NetStream.Play.Failed"))
            status = RTMP_NETSTREAM_PLAY_FAILED;
        else if (!strcmp(code->data, "NetStream.Play.StreamNotFound"))
            status = RTMP_NETSTREAM_PLAY_STREAM_NOT_FOUND;
        else if (!strcmp(code->data, "NetStream.Play.Reset"))
            status = RTMP_NETSTREAM_PLAY_RESET;
        else if (!strcmp(code->data, "NetStream.Play.PublishNotify"))
            status = RTMP_NETSTREAM_PLAY_PUBLISH_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Play.UnpublishNotify"))
            status = RTMP_NETSTREAM_PLAY_UNPUBLISH_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Pause.Notify"))
            status = RTMP_NETSTREAM_PAUSE_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Unpause.Notify"))
            status = RTMP_NETSTREAM_UNPAUSE_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Publish.Start"))
            status = RTMP_NETSTREAM_PUBLISH_START;
        else if (!strcmp(code->data, "NetStream.Publish.BadName"))
            status = RTMP_NETSTREAM_PUBLISH_BADNAME;
        else if (!strcmp(code->data, "NetStream.Publish.Idle"))
            status = RTMP_NETSTREAM_PUBLISH_IDLE;
        else if (!strcmp(code->data, "NetStream.Unpublish.Success"))
            status = RTMP_NETSTREAM_UNPUBLISH_SUCCESS;
        else if (!strcmp(code->data, "NetConnection.Connect.Failed"))
            status = RTMP_NETCONNECTION_FAILED;
        else if (!strcmp(code->data, "NetConnection.Connect.Closed"))
            status = RTMP_NETCONNECTION_CLOSED;
        else if (!strcmp(code->data, "NetConnection.Connect.Success"))
            status = RTMP_NETCONNECTION_SUCCESS;
        else if (!strcmp(code->data, "NetConnection.Connect.Rejected"))
            status = RTMP_NETCONNECTION_REJECTED;
        else if (!strcmp(code->data, "NetConnection.Connect.AppShutdown"))
            status = RTMP_NETCONNECTION_APP_SHUTDOWN;
        else if (!strcmp(code->data, "NetConnection.Connect.InvalidApp"))
            status = RTMP_NETCONNECTION_INVALID_APP;
    } else if (type == AMF0_TYPE_NUMBER) {
        --p;
        amf0_read_number(p, data + size - p, &n);
        status = lroundl(n);
    }
    sbuf_del(field_name);
    sbuf_del(code);
    return status;
}
