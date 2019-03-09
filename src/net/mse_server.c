#include "mse_server.h"
#include "event_loop.h"
#include "net.h"
#include "log.h"
#include "cbuffer.h"
#include "sbuf.h"
#include "list.h"
#include "fmp4_mux.h"
#include "list.h"
#include "base64.h"
#include "pack_util.h"
#include "net/nbuf.h"
#include "macro_util.h"
#include "net/tcp_chan.h"
#include "sha1.h"
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

enum ws_opcode {
    WS_OPCODE_CONTINUATION_FRAME = 0,
    WS_OPCODE_TEXT = 1,
    WS_OPCODE_BINARY = 2,
    WS_OPCODE_CLOSE = 8,
    WS_OPCODE_PING = 9,
    WS_OPCODE_PONG = 10,
};

struct ws_frame {
    uint8_t fin;
    uint8_t opcode;
    uint8_t mask;
    uint8_t mask_key[4];
    int payload_len;
    char *payload_data;
};

typedef struct http_peer_t http_peer_t;
typedef struct http_request_t http_request_t;
typedef struct http_response_t http_response_t;

struct gop_cache_entry {
    int video;
    int key_frame;
    int64_t pts;
    int32_t duration;
    sbuf_t *buf;
    struct list_head link;
};

struct mse_server_t {
    zl_loop_t *loop;
    tcp_srv_t *tcp_srv;

    struct list_head session_list;
    struct list_head peer_list;
};

struct mse_session_t {
    mse_server_t *srv;
    sbuf_t *path;
    sbuf_t *init_vseg_cache;    // video init segment
    sbuf_t *init_aseg_cache;    // audio init segment
    sbuf_t *codec_config_cache;
    int64_t next_vpts;
    int64_t next_apts;
    struct list_head gop_cache_list; // video and audio data segments
    struct list_head link;
};

typedef struct http_request_t {
    http_peer_t *peer;
    http_method_t method;
    char *path;
    int body_len;
    char *body;
    struct list_head header_list;
    struct list_head link;
} http_request_t;

typedef struct http_response_t {
    enum http_status_t status;
    int body_len;
    char *body;
} http_response_t;

struct http_peer_t {
    mse_server_t *srv;
    tcp_chan_t *chan;

    enum http_parse_state parse_state;
    sbuf_t *parse_buf;
    http_request_t *parse_request; // partial request waiting body

    sbuf_t *session_path;
    int session_init_vseg_sent;
    int session_init_aseg_sent;
    uint64_t session_next_vseq;
    uint64_t session_next_aseq;
    int64_t session_start_vpts;
    int64_t session_start_apts;

    int flag;
    int upgraded;
    struct list_head req_list;

    struct list_head link;
};

static void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata);
static void request_handler(http_peer_t *peer, http_request_t *req);
static void peer_data_handler(tcp_chan_t *chan, void *udata);
static void peer_error_handler(tcp_chan_t *chan, int status, void *udata);

static http_peer_t *http_peer_new(mse_server_t *srv, tcp_chan_t *chan);
static void http_peer_del(http_peer_t *peer);

static struct http_request_t *http_request_new(http_peer_t *peer);
static void http_request_del(http_request_t *req);

static void send_chunked_reply(http_peer_t *peer);
static void send_final_reply(http_peer_t *peer, http_status_t status);
static void send_upgrade_reply(http_peer_t *peer, const char *sec_key);
static void new_peer_send_segs(http_peer_t *peer);

static http_request_t *http_parse_request(http_peer_t *peer, const char *p,
                                          const char *const pend);
static int find_headers_end(const char *p, int size, int last_size);
static void http_consume_while_spaces(const char *p, const char *const pend,
                                      const char **pp);
static void http_consume_line_end(const char *p, const char *const pend,
                                  const char **pp);
static int http_parse_request_line(const char *p, const char *const pend,
                                   struct http_request_t *req, const char **pp);
static int http_parse_header(struct list_head *list, const char *p, const char *const pend,
                             struct http_request_t *req, const char **pp);
static int http_parse_method(const char *p, const char *const pend,
                             struct http_request_t *req, const char **pp);
static int http_parse_url(const char *p, const char *const pend,
                          struct http_request_t *req, const char **pp);

static void gop_cache_clear(struct list_head *list);
static void gop_cache_add(struct list_head *list, int video, int64_t pts,
                          int32_t duration, int key_frame, const void *buf, int size);
static void peer_ws_frame_handler(http_peer_t *peer, struct ws_frame *frame);
static void peer_ws_data_handler(http_peer_t *peer);
static void compute_sha1(void* input, size_t length, unsigned char* md);
static int same_session(sbuf_t *url1, sbuf_t *url2);

mse_server_t *mse_server_new(zl_loop_t *loop)
{
    assert(loop);

    mse_server_t* srv;
    int ret;
    srv = malloc(sizeof(mse_server_t));
    memset(srv, 0, sizeof(mse_server_t));
    srv->loop = loop;
    srv->tcp_srv = tcp_srv_new(loop); socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    INIT_LIST_HEAD(&srv->session_list);
    INIT_LIST_HEAD(&srv->peer_list);
    return srv;
}
zl_loop_t *mse_server_get_loop(mse_server_t *srv)
{
    return srv->loop;
}
int mse_server_bind(mse_server_t *srv, unsigned short port)
{
    return tcp_srv_bind(srv->tcp_srv, NULL, port);
}
void mse_server_del(mse_server_t *srv)
{
    mse_session_t *session, *tmp;
    list_for_each_entry_safe(session, tmp, &srv->session_list, link) {
        mse_session_del(session);
    }
    tcp_srv_del(srv->tcp_srv);
    free(srv);
}
int mse_server_start(mse_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, accept_handler, srv);
    return tcp_srv_listen(srv->tcp_srv);
}
void mse_server_stop(mse_server_t *srv)
{

}

void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    mse_server_t *srv = udata;
    http_peer_t *peer = http_peer_new(srv, chan);
    if (!peer) {
        LLOG(LL_ERROR, "http_peer_new error.");
        return;
    }
    tcp_chan_set_cb(peer->chan, peer_data_handler, NULL, peer_error_handler, peer);
}

http_peer_t *http_peer_new(mse_server_t *srv, tcp_chan_t *chan)
{
    http_peer_t *peer = malloc(sizeof(http_peer_t));
    if (peer == NULL)
        return NULL;
    memset(peer, 0, sizeof(http_peer_t));
    peer->srv = srv;
    peer->chan = chan;
    peer->parse_state = HTTP_PARSE_HEADER;
    peer->parse_buf = sbuf_new1(MAX_HTTP_HEADER_SIZE);
    peer->session_path = sbuf_new();
    INIT_LIST_HEAD(&peer->req_list);
    list_add(&peer->link, &srv->peer_list);
    return peer;
}

struct http_request_t *http_request_new(http_peer_t *peer)
{
    struct http_request_t *req;
    req = malloc(sizeof(http_request_t));
    if (req == NULL)
        return NULL;
    memset(req, 0, sizeof(http_request_t));
    req->peer = peer;
    req->method = INVALID_HTTP_METHOD;
    req->path = NULL;
    req->body = NULL;
    req->body_len = 0;
    INIT_LIST_HEAD(&req->header_list);
    INIT_LIST_HEAD(&req->link);
    return req;
}

void http_request_del(struct http_request_t *req)
{
    http_header_t *h, *tmp;
    list_for_each_entry_safe(h, tmp, &req->header_list, link) {
        free(h->name);
        free(h->value);
        free(h);
    }
    INIT_LIST_HEAD(&req->header_list);
    if (req->path)
        free(req->path);
    if (req->body)
        free(req->body);
    free(req);
}

void http_peer_del(http_peer_t *peer)
{
    if (peer->parse_request)
        http_request_del(peer->parse_request);
    tcp_chan_close(peer->chan, 0);
    sbuf_del(peer->parse_buf);
    sbuf_del(peer->session_path);
    list_del(&peer->link);
    free(peer);
}

const char *get_header(struct list_head *list, const char *name)
{
    http_header_t *h;
    list_for_each_entry(h, list, link) {
        if (!strcasecmp(h->name, name))
            return h->value;
    }
    return NULL;
}

/* 返回值：
 *  0   需要更多数据
 *  1   完整http头
 */
int find_headers_end(const char *p, int size, int last_size)
{
    int i, n;
again:
    i = last_size;
    while (i < size && p[i] != '\n')
        ++i;
    if (i == 0 || i >= size)
        return 0;

    n = i + 1;
    --i;
    while (i >= 0 && p[i] == '\r')
        --i;
    if (i >= 0 && p[i] == '\n')
        return n;
    if (n >= size) {
        return 0;
    } else {
        last_size = n;
        goto again;
    }
}

int http_parse_method(const char *p, const char *const pend,
                      struct http_request_t *req, const char **pp)
{
    char method[10];
    int ret;
    ret = sscanf(p, "%9[A-Z]", method);
    if (ret > 0) {
        if (strcmp(method, "HEAD") == 0)
            req->method = HTTP_METHOD_HEAD;
        else if (strcmp(method, "GET") == 0)
            req->method = HTTP_METHOD_GET;
        else if (strcmp(method, "POST") == 0)
            req->method = HTTP_METHOD_POST;
        else if (strcmp(method, "PUT") == 0)
            req->method = HTTP_METHOD_PUT;
        else if (strcmp(method, "DELETE") == 0)
            req->method = HTTP_METHOD_DELETE;
        else if (strcmp(method, "OPTIONS") == 0)
            req->method = HTTP_METHOD_OPTIONS;
        else if (strcmp(method, "TRACE") == 0)
            req->method = HTTP_METHOD_TRACE;
        else if (strcmp(method, "CONNECT") == 0)
            req->method = HTTP_METHOD_CONNECT;
        else
            return -1;
        *pp = p + strlen(method);
        return 0;
    }
    return -1;
}

int http_parse_url(const char *p, const char *const pend, struct http_request_t *req, const char **pp)
{
    int ret = sscanf(p, "%ms", &req->path);
    if (ret > 0) {
        *pp = p + strlen(req->path);
        return 0;
    } else {
        free(req->path);
        req->path = NULL;
        return -1;
    }
}

void http_consume_while_spaces(const char *p, const char *const pend, const char **pp)
{
    while (p < pend && (*p == ' ' || *p == '\t'))
        ++p;
    *pp = p;
}

void http_consume_line_end(const char *p, const char *const pend, const char **pp)
{
    while (p < pend && *p != '\n')
        ++p;
    if (p < pend && *p == '\n')
        ++p;
    *pp = p;
}

int http_parse_request_line(const char *p, const char *const pend,
                            struct http_request_t *req, const char **pp)
{
    int ret;
    ret = http_parse_method(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    http_consume_while_spaces(p, pend, &p);
    ret = http_parse_url(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    //ret = http_parse_version(p, pend, req, pp);
    //if (ret != 0)
        //goto err_out;
    http_consume_line_end(p, pend, &p);
err_out:
    *pp = p;
    return ret;
}

int http_parse_header(struct list_head *list,
                      const char *p, const char *const pend,
                      struct http_request_t *req, const char **pp)
{
    http_header_t *hdr = NULL;
    char *hdr_name = NULL;
    char *hdr_value = NULL;
    int ret;
    ret = sscanf(p, "%m[^: \r\n]", &hdr_name);
    if (ret > 0) {
        p += strlen(hdr_name);
    } else {
        ret = -1;
        goto err_out;
    }
    http_consume_while_spaces(p, pend, &p);
    if (*p++ != ':') {
        ret = -1;
        goto err_out;
    }
    http_consume_while_spaces(p, pend, &p);
    ret = sscanf(p, "%m[^\r\n]", &hdr_value);
    if (ret > 0) {
        p += strlen(hdr_value);
    } else {
        ret = -1;
        goto err_out;
    }
    http_consume_line_end(p, pend, &p);
    while (p < pend && (*p == ' ' || *p == '\t')) {
        http_consume_while_spaces(p, pend, &p);
        char *hdr_value_cont = NULL;
        ret = sscanf(p, "%m[^\r\n]", &hdr_value_cont);
        if (ret > 0) {
            p += strlen(hdr_value_cont);
            int value_len = strlen(hdr_value);
            int value_cont_len = strlen(hdr_value_cont);
            hdr_value = realloc(hdr_value, value_len + value_cont_len + 1);
            strcpy(hdr_value + value_len, hdr_value_cont);
            free(hdr_value_cont);
            http_consume_while_spaces(p, pend, &p);
        } else {
            free(hdr_value_cont);
            ret = -1;
            goto err_out;
        }
    }
    if (strcasecmp(hdr_name, "Content-Length") == 0) {
        char *end_ptr = NULL;
        unsigned long len = strtoul(hdr_value, &end_ptr, 10);
        if (*end_ptr == '\0') {
            req->body_len = len;
            req->body = realloc(req->body, len);
        } else {
            ret = -1;
            goto err_out;
        }
    }
    ret = 0;
    hdr = malloc(sizeof(http_header_t));
    hdr->name = hdr_name;
    hdr->value = hdr_value;
    hdr_name = NULL;
    hdr_value = NULL;
    list_add_tail(&hdr->link, list);
err_out:
    free(hdr_name);
    free(hdr_value);
    *pp = p;
    return ret;
}

http_request_t *http_parse_request(http_peer_t *peer, const char *p, const char *const pend)
{
    struct http_request_t *req;
    int ret;
    req = http_request_new(peer);
    if (!req)
        return NULL;
    ret = http_parse_request_line(p, pend, req, &p);
    if (ret != 0)
        goto err_out;
    do {
        ret = http_parse_header(&req->header_list, p, pend, req, &p);
    } while (ret == 0);
    http_consume_line_end(p, pend, &p);
    if (p < pend) {
        char *unparsed = malloc(pend - p + 1);
        if (unparsed) {
            memcpy(unparsed, p, pend - p);
            unparsed[pend - p] = '\0';
            LLOG(LL_ERROR, "parse error, remain '%s'", unparsed);
        } else {
            LLOG(LL_ERROR, "parse error, remain %zu characters", pend - p);
        }
        goto err_out;
    }
    return req;
err_out:
    if (req)
        http_request_del(req);
    return NULL;
}

void request_handler(http_peer_t *peer, http_request_t *req)
{
    if (peer->flag & HTTP_PEER_ERROR) {
        http_request_del(req);
        return;
    }

    list_add_tail(&req->link, &peer->req_list);
    if (peer->req_list.next != &req->link)
        return;

    LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);
    if (strstr(req->path, "/live") != req->path) {
        send_final_reply(peer, HTTP_STATUS_NOT_FOUND);
        list_del(&req->link);
        http_request_del(req);
        return;
    }

    sbuf_strcpy(peer->session_path, req->path);
    const char *key = get_header(&req->header_list, "Sec-WebSocket-Key");
    if (key) {
        LLOG(LL_TRACE, "upgrade to websocket");
        peer->upgraded = 1;
        send_upgrade_reply(peer, key);
    } else {
        send_chunked_reply(peer);
    }
    new_peer_send_segs(peer);
}

void peer_ws_frame_handler(http_peer_t *peer, struct ws_frame *frame)
{
    if (frame->opcode < WS_OPCODE_CLOSE)
        return;
    //LLOG(LL_TRACE, "got ws_frame fin=%hhu opcode=hhu mask=hhu payload={}",
    //		  (bool)frame->fin, frame->opcode, (bool)frame->mask, frame->payload_len);
    if (frame->opcode == WS_OPCODE_CLOSE)
        peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void peer_ws_data_handler(http_peer_t *peer)
{
    struct ws_frame frame;
    int i, expect_size = 0;
    while (!tcp_chan_read_buf_empty(peer->chan)) {
        if (peer->parse_buf->size < 2) {
            sbuf_appendc(peer->parse_buf, tcp_chan_readc(peer->chan));
        } else {
            char *p = peer->parse_buf->data;
            frame.fin = p[0] & 0x80;
            frame.opcode = p[0] & 0xf;
            frame.mask = p[1] & 0x80;
            frame.payload_len = p[1] & 0x7f;

            if (frame.payload_len == 126) {
                if (peer->parse_buf->size < 4) {
                    sbuf_appendc(peer->parse_buf, tcp_chan_readc(peer->chan));
                    continue;
                } else {
                    frame.payload_len = unpack_be16(peer->parse_buf + 2);
                    expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 4 - peer->parse_buf->size;
                }
            } else if (frame.payload_len == 127) {
                if (peer->parse_buf->size < 10) {
                    sbuf_appendc(peer->parse_buf, tcp_chan_readc(peer->chan));
                    continue;
                } else {
                    frame.payload_len = (int)unpack_be64(peer->parse_buf + 2);
                    expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 10 - peer->parse_buf->size;
                }
            } else {
                expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 2 - peer->parse_buf->size;
            }

            int old_size = peer->parse_buf->size;
            int buf_size = tcp_chan_get_read_buf_size(peer->chan);
            if (buf_size < expect_size) {
                sbuf_resize(peer->parse_buf, old_size + buf_size);
                tcp_chan_read(peer->chan, peer->parse_buf->data + old_size, buf_size);
                break;
            }

            sbuf_resize(peer->parse_buf, old_size + expect_size);
            tcp_chan_read(peer->chan, peer->parse_buf->data + old_size, expect_size);
            if (frame.mask)
                memcpy(frame.mask_key, sbuf_tail(peer->parse_buf) - frame.payload_len - 4, 4);
            frame.payload_data = sbuf_tail(peer->parse_buf) - frame.payload_len;
            peer_ws_frame_handler(peer, &frame);
            sbuf_clear(peer->parse_buf);
        }
    }
}

void peer_data_handler(tcp_chan_t *chan, void *udata)
{
    http_peer_t *peer = udata;
    while (!tcp_chan_read_buf_empty(chan)) {
        if (peer->upgraded) {
            peer_ws_data_handler(peer);
        } else {
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
                    peer->parse_request = NULL;
                    peer->parse_state = HTTP_PARSE_HEADER;
                } else {
                    break;
                }
            } else {
                assert(0);
            }
        }
    }
    if ((peer->flag & HTTP_PEER_ERROR)
        || (peer->flag & HTTP_PEER_CLOSE_ASAP)) {
        http_peer_del(peer);
    }
}

void peer_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    http_peer_t *peer = udata;
    http_peer_del(peer);
}

void send_final_reply(http_peer_t *peer, http_status_t status)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 %d %s\r\n\r\n",
                     status, http_strstatus(status));
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void send_chunked_reply(http_peer_t *peer)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    http_status_t status = HTTP_STATUS_OK;
    char *s;
    int n = asprintf(&s,
                     "HTTP/1.1 %d %s\r\n"
                     "Server: mse server\r\n"
                     "Connection: keep-alive\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Transfer-Encoding: chunked\r\n"
                     "Content-Type: video/mp4\r\n"
                     "\r\n",
                     status, http_strstatus(status));
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
}

void compute_sha1(void *input, size_t length, unsigned char *digest)
{
    SHA1_CTX context;
    SHA1Init(&context);
    SHA1Update(&context, input, length);
    SHA1Final(digest, &context);
}

void send_upgrade_reply(http_peer_t *peer, const char *client_key)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;

    sbuf_t *sec_key = sbuf_strdup(client_key);
    sbuf_append1(sec_key, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    char sha1[21] = {};
    compute_sha1(sec_key->data, sec_key->size, sha1);
    char sec_result[40];
    int n = base64_encode(sha1, 20, NULL, 0);
    assert(n < sizeof(sec_result));
    base64_encode(sha1, 20, sec_result, n);
    sec_result[n] = 0;

    char *s;
    http_status_t status = HTTP_STATUS_SWITCHING_PROTOCOLS;
    n = asprintf(&s,
                 "HTTP/1.1 %d %s\r\n"
                 "Server: mse server\r\n"
                 "Connection: upgrade\r\n"
                 "Upgrade: WebSocket\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Access-Control-Allow-Credentials: true\r\n"
                 "Access-Control-Allow-Headers: content-type\r\n"
                 "Sec-WebSocket-Accept: %s\r\n"
                 "\r\n",
                 status, http_strstatus(status), sec_result);
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
}

/**
 * Transfer-Encoding: chunked
 *      hex-data-size\r\n
 *      data-raw-bytes...\r\n
 *
 *      ......
 *
 *      0\r\n\r\n
 */
void send_chunked_data(http_peer_t *peer, const void *data, int size)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    if (peer->upgraded) {
        char header[10];
        int n = 0;
        header[0] = 0x82; // OPCODE_BINARY
        if (size > 65535) {
            header[1] = 127;
            pack_be64(&header[2], size);
            n = 10;
        } else if (size > 125) {
            header[1] = 126;
            pack_be16(&header[2], size);
            n = 4;
        } else {
            header[1] = size;
            n = 2;
        }
        tcp_chan_write(peer->chan, header, n);
        tcp_chan_write(peer->chan, data, size);
    } else {
        char *s;
        int n = asprintf(&s, "%x\r\n", size);
        if (n <= 0)
            return;
        tcp_chan_write(peer->chan, s, n);
        free(s);
        tcp_chan_write(peer->chan, data, size);
        tcp_chan_write(peer->chan, "\r\n", 2);
    }
}

mse_session_t *mse_session_new(mse_server_t *srv, const char *path)
{
    mse_session_t *session;
    session = malloc(sizeof(mse_session_t));
    memset(session, 0, sizeof(mse_session_t));
    session->srv = srv;
    session->path = sbuf_strdup(path);
    session->init_vseg_cache = sbuf_new();
    session->init_aseg_cache = sbuf_new();
    session->codec_config_cache = sbuf_new();
    session->next_vpts = session->next_apts = INT64_MIN;
    INIT_LIST_HEAD(&session->gop_cache_list);
    list_add(&session->link, &srv->session_list);
    return session;
}

void mse_session_del(mse_session_t *session)
{
    http_peer_t *peer, *tmp;
    list_for_each_entry_safe(peer, tmp, &session->srv->peer_list, link) {
        if (same_session(session->path, peer->session_path)) {
            http_peer_del(peer);
        }
    }

    sbuf_del(session->init_vseg_cache);
    sbuf_del(session->init_aseg_cache);
    sbuf_del(session->codec_config_cache);
    gop_cache_clear(&session->gop_cache_list);
    sbuf_del(session->path);
    list_del(&session->link);
    free(session);
}

int mse_session_update_codec_info(mse_session_t *session, const char *data, int size)
{
    if (session->codec_config_cache->size != size
        || memcmp(data, session->codec_config_cache->data, size)) {

        sbuf_strncpy(session->codec_config_cache, data, size);
        return 1;
    }
    return 0;
}

void mse_session_set_video_codec_h264(mse_session_t *session, const char *data, int size)
{
    int changed = mse_session_update_codec_info(session, data, size);
    if (!changed)
        return;

    LLOG(LL_TRACE, "codec changed");

    sbuf_t *buf = fmp4_mux_init_seg(0, data, size);
    sbuf_clear(session->init_vseg_cache);
    sbuf_append(session->init_vseg_cache, buf);
    gop_cache_clear(&session->gop_cache_list);
    http_peer_t *peer, *tmp;
    list_for_each_entry_safe(peer, tmp, &session->srv->peer_list, link) {
        if (same_session(session->path, peer->session_path)) {
            peer->session_init_vseg_sent = 1;

            send_chunked_data(peer, session->init_vseg_cache->data, session->init_vseg_cache->size);
        }
    }
    sbuf_del(buf);
}

void mse_session_set_audio_codec_flac(mse_session_t *session, const char *data, int size)
{
    sbuf_t *buf = fmp4_mux_init_seg(1, data, size);
    sbuf_clear(session->init_aseg_cache);
    sbuf_append(session->init_aseg_cache, buf);
    http_peer_t *peer;
    list_for_each_entry(peer, &session->srv->peer_list, link) {
        if (same_session(session->path, peer->session_path)
            && !peer->session_init_aseg_sent) {

            peer->session_init_aseg_sent = 1;
            send_chunked_data(peer, session->init_aseg_cache->data, session->init_aseg_cache->size);
        }
    }
    sbuf_del(buf);
}

void mse_session_push_video(mse_session_t *session, int64_t pts, int32_t duration,
                            int key_frame, const char *data, int size)
{
    //LLOG(LL_TRACE, "video pts=%lld", (long long)pts);
    http_peer_t *peer;

    if (session->next_vpts != INT64_MIN) {
        if (session->next_vpts < pts) { // video gap
            duration = (pts + duration) - session->next_vpts;
            pts = session->next_vpts;
            LLOG(LL_TRACE, "video gap detected, update pts=%ld duration=%d", pts, duration);
        } else if (session->next_vpts > pts) { // video early
            if (pts + duration > session->next_vpts) {
                duration = (pts + duration) - session->next_vpts;
            } else {
                duration = 0;
            }
            pts = session->next_vpts;
        }
    }
    session->next_vpts = pts + duration;

    if (key_frame) {
        gop_cache_clear(&session->gop_cache_list);
        gop_cache_add(&session->gop_cache_list, 1, pts, duration, key_frame, data, size);
    } else if (!list_empty(&session->gop_cache_list)) {
        gop_cache_add(&session->gop_cache_list, 1, pts, duration, key_frame, data, size);
    }

    list_for_each_entry(peer, &session->srv->peer_list, link) {
        if (same_session(session->path, peer->session_path)
            && peer->session_init_vseg_sent) {

            if (peer->session_next_vseq == 0)
                peer->session_start_vpts = pts;

            sbuf_t *buf = fmp4_mux_media_seg(0, peer->session_next_vseq++, pts - peer->session_start_vpts,
                                             duration, key_frame, data, size);
            send_chunked_data(peer, buf->data, buf->size);
            sbuf_del(buf);
        }
    }
}

void mse_session_push_audio(mse_session_t *session, int64_t pts, int32_t duration,
                            int key_frame, const char *data, int size)
{
    //LLOG(LL_TRACE, "audio pts=%lld", (long long)pts);
    http_peer_t *peer;

    if (!list_empty(&session->gop_cache_list)) {
        gop_cache_add(&session->gop_cache_list, 0, pts, duration, key_frame, data, size);
    }

    list_for_each_entry(peer, &session->srv->peer_list, link) {
        if (same_session(session->path, peer->session_path)
            && peer->session_init_aseg_sent) {

            if (peer->session_next_aseq == 0)
                peer->session_start_apts = pts;

            sbuf_t *buf = fmp4_mux_media_seg(1, peer->session_next_aseq++, pts - peer->session_start_apts,
                                             duration, key_frame, data, size);
            send_chunked_data(peer, buf->data, buf->size);
            sbuf_del(buf);
        }
    }
}

void new_peer_send_segs(http_peer_t *peer)
{
    mse_session_t *session = NULL, *tmp;
    list_for_each_entry(tmp, &peer->srv->session_list, link) {
        if (same_session(tmp->path, peer->session_path)) {
            session = tmp;
            break;
        }
    }
    if (session) {
        if (!sbuf_empty(session->init_vseg_cache)) {

            LLOG(LL_TRACE, "send init_vseg %d", session->init_vseg_cache->size);
            peer->session_init_vseg_sent = 1;
            send_chunked_data(peer, session->init_vseg_cache->data,
                              session->init_vseg_cache->size);
        }
        if (!sbuf_empty(session->init_aseg_cache)) {

            LLOG(LL_TRACE, "send init_aseg %d", session->init_aseg_cache->size);
            peer->session_init_aseg_sent = 1;
            send_chunked_data(peer, session->init_aseg_cache->data,
                              session->init_aseg_cache->size);
        }

        if (peer->session_init_vseg_sent && !list_empty(&session->gop_cache_list)) {
            LLOG(LL_TRACE, "send cached gop");
            struct gop_cache_entry *e;
            list_for_each_entry(e, &session->gop_cache_list, link) {
                int idx;
                unsigned seq;
                int64_t pts;
                if (e->video) {
                    idx = 0;
                    seq = peer->session_next_vseq++;
                    if (seq == 0)
                        peer->session_start_vpts = e->pts;
                    pts = e->pts - peer->session_start_vpts;
                } else {
                    idx = 1;
                    seq = peer->session_next_aseq++;
                    if (seq == 0)
                        peer->session_start_apts = e->pts;
                    pts = e->pts - peer->session_start_apts;
                }
                sbuf_t *buf = fmp4_mux_media_seg(idx, seq, pts, e->duration, e->key_frame,
                                                 e->buf->data, e->buf->size);
                send_chunked_data(peer, buf->data, buf->size);
                sbuf_del(buf);
            }
        }
    }
}

void gop_cache_clear(struct list_head *list)
{
    struct gop_cache_entry *e, *tmp;
    list_for_each_entry_safe(e, tmp, list, link) {
        sbuf_del(e->buf);
        free(e);
    }
    INIT_LIST_HEAD(list);
}

void gop_cache_add(struct list_head *list, int video,
                   int64_t pts, int32_t duration, int key_frame,
                   const void *data, int size)
{
    struct gop_cache_entry *e;
    e = malloc(sizeof(struct gop_cache_entry));
    e->video = video;
    e->key_frame = key_frame;
    e->pts = pts;
    e->duration = duration;
    e->buf = sbuf_strndup(data, size);
    list_add_tail(&e->link, list);
}

int same_session(sbuf_t *url1, sbuf_t *url2)
{
    if (!strcmp(url1->data, url2->data))
        return 1;
    char *s1 = strcasestr(url1->data, "tId=");
    char *s2 = strcasestr(url2->data, "tId=");
    if (s1 && s2 && !strcasecmp(s1, s2)) {
        return 1;
    } else {
        return 0;
    }
}
