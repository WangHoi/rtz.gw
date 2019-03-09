#include "monitor_server.h"
#include "event_loop.h"
#include "net_util.h"
#include "log.h"
#include "sbuf.h"
#include "list.h"
#include "list.h"
#include "pack_util.h"
#include "net/nbuf.h"
#include "macro_util.h"
#include "tcp_chan.h"
#include "sha1.h"
#include "rtz_server.h"
#include "rtmp_server.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <sys/uio.h>

enum http_parse_state {
    HTTP_PARSE_HEADER,
    HTTP_PARSE_BODY,
};

enum http_peer_flag {
    HTTP_PEER_CLOSE_ASAP = 1,
    HTTP_PEER_ERROR = 2,
};

typedef struct monitor_peer_t monitor_peer_t;

struct monitor_server_t {
    zl_loop_t *loop;
    rtz_server_t *rtz_srv;
    rtmp_server_t *rtmp_srv;
    tcp_srv_t *tcp_srv;

    struct list_head peer_list;
};

struct monitor_peer_t {
    monitor_server_t *srv;
    tcp_chan_t *chan;

    enum http_parse_state parse_state;
    sbuf_t *parse_buf;
    http_request_t *parse_request; // partial request waiting body

    int flag;

    struct list_head link;
};

static void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata);
static void request_handler(monitor_peer_t *peer, http_request_t *req);
static void peer_data_handler(tcp_chan_t *chan, void *udata);
static void peer_error_handler(tcp_chan_t *chan, int status, void *udata);

static monitor_peer_t *monitor_peer_new(monitor_server_t *srv, tcp_chan_t *chan);
static void monitor_peer_del(monitor_peer_t *peer, int flush_write);

static void send_final_reply(monitor_peer_t *peer, http_status_t status);
static void send_final_reply_json(monitor_peer_t *peer, http_status_t status, const char *body);

monitor_server_t *monitor_server_new(zl_loop_t *loop, rtz_server_t *rtz_srv, rtmp_server_t *rtmp_srv)
{
    assert(loop);

    monitor_server_t* srv;
    int ret;

    srv = malloc(sizeof(monitor_server_t));
    memset(srv, 0, sizeof(monitor_server_t));
    srv->loop = loop;
    srv->rtz_srv = rtz_srv;
    srv->rtmp_srv = rtmp_srv;
    srv->tcp_srv = tcp_srv_new(loop); socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    INIT_LIST_HEAD(&srv->peer_list);
    return srv;
}
zl_loop_t *monitor_server_get_loop(monitor_server_t *srv)
{
    return srv->loop;
}
int monitor_server_bind(monitor_server_t *srv, unsigned short port)
{
    return tcp_srv_bind(srv->tcp_srv, NULL, port);
}
void monitor_server_del(monitor_server_t *srv)
{
    monitor_peer_t *p, *ptmp;
    list_for_each_entry_safe(p, ptmp, &srv->peer_list, link) {
        monitor_peer_del(p, 0);
    }
    tcp_srv_del(srv->tcp_srv);
    free(srv);
}
int monitor_server_start(monitor_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, accept_handler, srv);
    return tcp_srv_listen(srv->tcp_srv);
}
void monitor_server_stop(monitor_server_t *srv)
{

}

void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    monitor_server_t *srv = udata;
    monitor_peer_t *peer = monitor_peer_new(srv, chan);
    if (!peer) {
        LLOG(LL_ERROR, "monitor_peer_new error.");
        return;
    }
    tcp_chan_set_cb(peer->chan, peer_data_handler, NULL, peer_error_handler, peer);
}

monitor_peer_t *monitor_peer_new(monitor_server_t *srv, tcp_chan_t *chan)
{
    monitor_peer_t *peer = malloc(sizeof(monitor_peer_t));
    if (peer == NULL)
        return NULL;
    memset(peer, 0, sizeof(monitor_peer_t));
    peer->srv = srv;
    peer->chan = chan;
    peer->parse_state = HTTP_PARSE_HEADER;
    peer->parse_buf = sbuf_new1(MAX_HTTP_HEADER_SIZE);
    list_add(&peer->link, &srv->peer_list);
    return peer;
}

void monitor_peer_del(monitor_peer_t *peer, int flush_write)
{
    if (peer->parse_request)
        http_request_del(peer->parse_request);
    tcp_chan_close(peer->chan, flush_write);
    sbuf_del(peer->parse_buf);
    list_del(&peer->link);
    free(peer);
}

void request_handler(monitor_peer_t *peer, http_request_t *req)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;

    //LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);
    const char *stream_name = strstr(req->path, "stream=");
    if (stream_name)
        stream_name += strlen("stream=");
    if (stream_name) {
        int nb_publish, nb_play, nb_play2;
        rtz_get_stream_info(peer->srv->rtz_srv, stream_name, &nb_publish, &nb_play);
        rtmp_get_player(peer->srv->rtmp_srv, stream_name, &nb_play2);
        LLOG(LL_TRACE, "handle: stream=%s publishers=%d players=%d(%d+%d)",
             stream_name, nb_publish, nb_play + nb_play2, nb_play, nb_play2);
        char json[256];
        snprintf(json, sizeof(json), "{\"code\":0,\"nb_publish\":%d,\"nb_play\":%d}",
                 nb_publish, nb_play + nb_play2);
        send_final_reply_json(peer, HTTP_STATUS_OK, json);
    } else {
        send_final_reply(peer, HTTP_STATUS_INTERNAL_SERVER_ERROR);
    }
}


void peer_data_handler(tcp_chan_t *chan, void *udata)
{
    monitor_peer_t *peer = udata;
    while (!tcp_chan_read_buf_empty(chan)) {
        if (peer->parse_state == HTTP_PARSE_HEADER) {
            char c = tcp_chan_readc(chan);
            sbuf_appendc(peer->parse_buf, c);
            if (sbuf_ends_with(peer->parse_buf, "\r\n\r\n")) {
                http_request_t *req = http_parse_request(peer, peer->parse_buf->data,
                                                         sbuf_tail(peer->parse_buf));
                sbuf_clear(peer->parse_buf);
                if (req) {
                    peer->parse_request = req;
                    if (req->body_len) {
                        peer->parse_state = HTTP_PARSE_BODY;
                    } else {
                        request_handler(peer, req);
                        http_request_del(req);
                        peer->parse_request = NULL;
                    }
                } else {
                    send_final_reply(peer, HTTP_STATUS_BAD_REQUEST);
                }
            }
        } else if (peer->parse_state == HTTP_PARSE_BODY) {
            if (peer->parse_request->body_len <= tcp_chan_get_read_buf_size(chan)) {
                tcp_chan_read(chan, peer->parse_request->body,
                                peer->parse_request->body_len);
                request_handler(peer, peer->parse_request);
                http_request_del(peer->parse_request);
                peer->parse_request = NULL;
                peer->parse_state = HTTP_PARSE_HEADER;
            } else {
                break;
            }
        } else {
            assert(0);
        }
    }
    if ((peer->flag & HTTP_PEER_ERROR)
        || (peer->flag & HTTP_PEER_CLOSE_ASAP)) {
        monitor_peer_del(peer, 1);
    }
}

void peer_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    monitor_peer_t *peer = udata;
    monitor_peer_del(peer, 0);
}

void send_final_reply(monitor_peer_t *peer, http_status_t status)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 %d %s\r\n"
                     "Connection:close\r\n"
                     "\r\n",
                     status, http_strstatus(status));
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void send_final_reply_json(monitor_peer_t *peer, http_status_t status, const char *body)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 %d %s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zd\r\n"
                     "Connection:close\r\n"
                     "\r\n%s",
                     status, http_strstatus(status),
                     strlen(body), body);
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}
