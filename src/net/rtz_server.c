#include "rtz_server.h"
#include "event_loop.h"
#include "net_util.h"
#include "log.h"
#include "cbuf.h"
#include "sbuf.h"
#include "list.h"
#include "rtp.h"
#include "algo/base64.h"
#include "pack_util.h"
#include "net/nbuf.h"
#include "macro_util.h"
#include "net/tcp_chan.h"
#include "net/tcp_chan_ssl.h"
#include "net/udp_chan.h"
#include "algo/sha1.h"
#include "ice.h"
#include "dtls.h"
#include "media/rtp_mux.h"
#include "apierror.h"
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
#include <cJSON.h>

extern const char *RTZ_LOCAL_IP;
extern const char *RTZ_PUBLIC_IP;
extern int RTZ_PUBLIC_MEDIA_PORT;
extern int RTZ_LOCAL_MEDIA_PORT;

#define MAX_PLAYOUT_DELAY_FRAMES 50

enum http_parse_state {
    HTTP_PARSE_HEADER,
    HTTP_PARSE_BODY,
};

enum http_peer_flag {
    HTTP_PEER_CLOSE_ASAP = 1,
    HTTP_PEER_ERROR = 2,
};

enum {
    RTZ_HANDLE_PREPARING = 1,
    RTZ_HANDLE_STARTING = 2,
    RTZ_HANDLE_RTC_UP = 4,
    RTZ_HANDLE_STARTED = 8,
};

typedef struct http_peer_t http_peer_t;

#if RTZ_SERVER_SSL
#define TCP_SRV_T tcp_srv_ssl_t
#define TCP_SRV_BIND tcp_srv_ssl_bind
#define TCP_SRV_LISTEN tcp_srv_ssl_listen
#define TCP_SRV_SET_CB tcp_srv_ssl_set_cb
#define TCP_SRV_NEW tcp_srv_ssl_new
#define TCP_SRV_DEL tcp_srv_ssl_del
#define TCP_CHAN_T tcp_chan_ssl_t
#define TCP_CHAN_CLOSE tcp_chan_ssl_close
#define TCP_CHAN_SET_CB tcp_chan_ssl_set_cb
#define TCP_CHAN_READC tcp_chan_ssl_readc
#define TCP_CHAN_READ_BUF_EMPTY tcp_chan_ssl_read_buf_empty
#define TCP_CHAN_GET_READ_BUF_SIZE tcp_chan_ssl_get_read_buf_size
#define TCP_CHAN_READ tcp_chan_ssl_read
#define TCP_CHAN_WRITE tcp_chan_ssl_write
#else
#define TCP_SRV_T tcp_srv_t
#define TCP_SRV_BIND tcp_srv_bind
#define TCP_SRV_LISTEN tcp_srv_listen
#define TCP_SRV_SET_CB tcp_srv_set_cb
#define TCP_SRV_NEW tcp_srv_new
#define TCP_SRV_DEL tcp_srv_del
#define TCP_CHAN_T tcp_chan_t
#define TCP_CHAN_CLOSE tcp_chan_close
#define TCP_CHAN_SET_CB tcp_chan_set_cb
#define TCP_CHAN_READC tcp_chan_readc
#define TCP_CHAN_READ_BUF_EMPTY tcp_chan_read_buf_empty
#define TCP_CHAN_GET_READ_BUF_SIZE tcp_chan_get_read_buf_size
#define TCP_CHAN_READ tcp_chan_read
#define TCP_CHAN_WRITE tcp_chan_write
#endif

struct rtz_server_t {
    zl_loop_t *loop;
    TCP_SRV_T *tcp_srv;
    ice_server_t *ice_srv;

    struct list_head peer_list;     /* http_peer_t list */
    struct list_head session_list;  /* rtz_session_t list */
    struct list_head stream_list;   /* rtz_stream_t list */
};

struct http_peer_t {
    rtz_server_t *srv;
    TCP_CHAN_T *chan;

    enum http_parse_state parse_state;
    sbuf_t *parse_buf;
    http_request_t *parse_request; // partial request waiting body

    int flag;
    int upgraded;
    struct list_head req_list;

    sbuf_t *url_path;

    struct list_head link;
};

typedef struct rtz_session_t {
    rtz_server_t *srv;
    http_peer_t *peer;
    sbuf_t *id;
    struct list_head link;          /* link to rtz_server_t.session_list */
    struct list_head handle_list;
} rtz_session_t;

typedef struct rtz_handle_t {
    sbuf_t *id;
    sbuf_t *url;
    sbuf_t *app;
    sbuf_t *tc_url;
    sbuf_t *stream_name;
    rtz_stream_t *stream;
    rtz_session_t *session;
    ice_agent_t *ice;
    int flag;
    int sdp_version;
    uint16_t min_playout_delay;     /* frames: nodelay:0, balanced:8, smooth:16 */
    struct list_head link;          /* link to rtz_session_t.handle_list */
    struct list_head stream_link;   /* link to rtz_stream_t.handle_list */
} rtz_handle_t;

struct rtz_stream_t {
    rtz_server_t *srv;
    sbuf_t *stream_name;
    rtp_mux_t *rtp_mux;
    uint16_t sframe_time;
    long long last_time;
    struct list_head link;
    struct list_head handle_list;
#ifdef ENABLE_RTP_TESTCHAN
    udp_chan_t *test_chan;
#endif
};

static void accept_handler(TCP_SRV_T *tcp_srv, TCP_CHAN_T *chan, void *udata);
static void http_request_handler(http_peer_t *peer, http_request_t *req);
static void peer_data_handler(TCP_CHAN_T *chan, void *udata);
static void peer_error_handler(TCP_CHAN_T *chan, int status, void *udata);

static http_peer_t *http_peer_new(rtz_server_t *srv, TCP_CHAN_T *chan);
static void http_peer_del(http_peer_t *peer);

static void send_final_reply(http_peer_t *peer, http_status_t status);
static void send_upgrade_reply(http_peer_t *peer, const char *sec_key);
static void send_json(http_peer_t *peer, cJSON *json);
static void send_error(http_peer_t *peer, const char *session_id, const char *handle_id,
                       int error, const char *format, ...) __attribute__((format(printf, 5, 6)));

static void peer_ws_frame_handler(http_peer_t *peer, struct ws_frame *frame);
static void peer_ws_data_handler(http_peer_t *peer);
static void compute_sha1(void* input, size_t length, unsigned char* md);
static void send_ws_frame(http_peer_t *peer, int text, const void *data, int size);

static void create_session(http_peer_t *peer, const char *transaction);
static void destroy_session(http_peer_t *peer, const char *transaction, const char *session_id);
static void create_handle(http_peer_t *peer, const char *transaction, const char *session_id,
                          const char *url, const char *transport, uint16_t min_playout_delay);
static void destroy_handle(http_peer_t *peer, const char *transaction,
                           const char *session_id, const char *handle_id);
static void handle_message(http_peer_t *peer, const char *transaction,
                           const char *session_id, const char *handle_id,
                           cJSON *body, cJSON *jsep);
static rtz_session_t *find_session(rtz_server_t *srv, const char *session_id);
static rtz_handle_t *find_handle(rtz_server_t *srv, const char *session_id,
                                 const char *handle_id);
static rtz_stream_t *find_stream(rtz_server_t *srv, const char *stream_name);
static void process_sdp_answer(http_peer_t *peer, const char *transaction,
                               const char *session_id, const char *handle_id,
                               const char *sdp);
static void send_rtp(rtz_handle_t *handle, int video, const void *data, int size);
static void rtp_mux_handler(int video, int kf, void *data, int size, void *udata);
static sbuf_t *create_sdp(rtz_handle_t *handle, int tcp);
static void rtz_handle_del(rtz_handle_t *handle);
static void rtz_session_del(rtz_session_t *session);
static void parse_url(rtz_handle_t *h, const char *url);
static cJSON *make_streaming_event(rtz_handle_t *handle, const char *ename, cJSON **presult);

rtz_server_t *rtz_server_new(zl_loop_t *loop)
{
    assert(loop);

    rtz_server_t* srv;
    int ret;
    srv = malloc(sizeof(rtz_server_t));
    memset(srv, 0, sizeof(rtz_server_t));
    srv->loop = loop;
    srv->tcp_srv = TCP_SRV_NEW(loop);
    srv->ice_srv = ice_server_new(loop);
    ice_server_bind(srv->ice_srv, RTZ_LOCAL_IP, RTZ_LOCAL_MEDIA_PORT);
    ice_server_start(srv->ice_srv);
    INIT_LIST_HEAD(&srv->peer_list);
    INIT_LIST_HEAD(&srv->session_list);
    INIT_LIST_HEAD(&srv->stream_list);
    return srv;
}

zl_loop_t *rtz_server_get_loop(rtz_server_t *srv)
{
    return srv->loop;
}

int rtz_server_bind(rtz_server_t *srv, unsigned short port)
{
    return TCP_SRV_BIND(srv->tcp_srv, NULL, port);
}

void rtz_server_del(rtz_server_t *srv)
{
    rtz_server_stop(srv);

    ice_server_del(srv->ice_srv);
    TCP_SRV_DEL(srv->tcp_srv);
    free(srv);
}
int rtz_server_start(rtz_server_t *srv)
{
    TCP_SRV_SET_CB(srv->tcp_srv, accept_handler, srv);
    return TCP_SRV_LISTEN(srv->tcp_srv);
}
void rtz_server_stop(rtz_server_t *srv)
{
    http_peer_t *p, *tmp;
    list_for_each_entry_safe(p, tmp, &srv->peer_list, link) {
        http_peer_del(p);
    }
    rtz_session_t *s, *stmp;
    list_for_each_entry_safe(s, stmp, &srv->session_list, link) {
        rtz_session_del(s);
    }
}

void accept_handler(TCP_SRV_T *tcp_srv, TCP_CHAN_T *chan, void *udata)
{
    rtz_server_t *srv = udata;
    http_peer_t *peer = http_peer_new(srv, chan);
    if (!peer) {
        LLOG(LL_ERROR, "http_peer_new error.");
        return;
    }
    TCP_CHAN_SET_CB(peer->chan, peer_data_handler, NULL, peer_error_handler, peer);
}

http_peer_t *http_peer_new(rtz_server_t *srv, TCP_CHAN_T *chan)
{
    http_peer_t *peer = malloc(sizeof(http_peer_t));
    if (peer == NULL)
        return NULL;
    memset(peer, 0, sizeof(http_peer_t));
    peer->srv = srv;
    peer->chan = chan;
    peer->parse_state = HTTP_PARSE_HEADER;
    peer->parse_buf = sbuf_new1(MAX_HTTP_HEADER_SIZE);
    peer->url_path = sbuf_new();
    INIT_LIST_HEAD(&peer->req_list);
    list_add(&peer->link, &srv->peer_list);
    return peer;
}

void http_peer_del(http_peer_t *peer)
{
    if (peer->parse_request)
        http_request_del(peer->parse_request);
    rtz_session_t *s, *tmp;
    list_for_each_entry_safe(s, tmp, &peer->srv->session_list, link) {
        if (s->peer == peer) {
            LLOG(LL_ERROR, "release session %p sid='%s'", s, s->id->data);
            rtz_session_del(s);
        }
    }
    TCP_CHAN_CLOSE(peer->chan, 0);
    sbuf_del(peer->parse_buf);
    sbuf_del(peer->url_path);
    list_del(&peer->link);
    free(peer);
}

void http_request_handler(http_peer_t *peer, http_request_t *req)
{
    if (peer->flag & HTTP_PEER_ERROR) {
        http_request_del(req);
        return;
    }

    list_add_tail(&req->link, &peer->req_list);
    if (peer->req_list.next != &req->link)
        return;

    LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);
    if (strstr(req->path, "/rtz") != req->path) {
        send_final_reply(peer, HTTP_STATUS_INTERNAL_SERVER_ERROR);
        list_del(&req->link);
        http_request_del(req);
        return;
    }

    sbuf_strcpy(peer->url_path, req->path);
    const char *key = http_get_header(&req->header_list, "Sec-WebSocket-Key");
    if (key) {
        //LLOG(LL_TRACE, "upgrade to websocket");
        peer->upgraded = 1;
        send_upgrade_reply(peer, key);
        http_request_del(req);
    }
}

void peer_ws_frame_handler(http_peer_t *peer, struct ws_frame *frame)
{
    //LLOG(LL_TRACE, "got ws_frame fin=%hhu opcode=%hhu mask=%hhu payload_len=%d",
    // 	 frame->fin, frame->opcode, frame->mask, frame->payload_len);
    if (frame->opcode == WS_OPCODE_CLOSE) {
        peer->flag |= HTTP_PEER_CLOSE_ASAP;
    } else if (frame->opcode == WS_OPCODE_PING) {
        send_ws_frame(peer, WS_OPCODE_PONG, frame->payload_data, frame->payload_len);
    } else if (frame->opcode == WS_OPCODE_TEXT) {
        //LLOG(LL_TRACE, "payload='%s'", strndup(frame->payload_data, frame->payload_len));
        cJSON *json = cJSON_ParseWithOpts(frame->payload_data, NULL, cJSON_False);
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(json, "type"));
        const char *transaction = cJSON_GetStringValue(cJSON_GetObjectItem(json, "transaction"));
        const char *session_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "session_id"));
        const char *handle_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "handle_id"));
        if (type && transaction) {

            if (!strcmp(type, "createSession")) {
                create_session(peer, transaction);
            } else if (!strcmp(type, "destroySession")) {
                destroy_session(peer, transaction, session_id);
            } else if (!strcmp(type, "createHandle")) {
                const char *url = cJSON_GetStringValue(cJSON_GetObjectItem(json, "url"));
                const char *transport = cJSON_GetStringValue(cJSON_GetObjectItem(json, "transport"));
                cJSON *min_playout_delay_json = cJSON_GetObjectItem(json, "min_delay");
                uint16_t min_playout_delay = 0;
                if (cJSON_IsNumber(min_playout_delay_json))
                    min_playout_delay = (uint16_t)min_playout_delay_json->valueint;
                if (min_playout_delay > MAX_PLAYOUT_DELAY_FRAMES)
                    min_playout_delay = MAX_PLAYOUT_DELAY_FRAMES;
                create_handle(peer, transaction, session_id, url, transport, min_playout_delay);
            } else if (!strcmp(type, "destroyHandle")) {
                destroy_handle(peer, transaction, session_id, handle_id);
            } else if (!strcmp(type, "message")) {
                cJSON *body = cJSON_GetObjectItem(json, "body");
                cJSON *jsep = cJSON_GetObjectItem(json, "jsep");
                handle_message(peer, transaction, session_id, handle_id, body, jsep);
            } else if (!strcmp(type, "keepalive")) {
                /* TODO: update session liveness */
            } else if (!strcmp(type, "trickle")) {
                /* ignore */
            } else {
                char *body = strndup(frame->payload_data, frame->payload_len);
                if (body) {
                    LLOG(LL_WARN, "unhandled type='%s' body='%s'", type, body);
                    free(body);
                }
            }
        }
        cJSON_Delete(json);
    }
}

void peer_ws_data_handler(http_peer_t *peer)
{
    struct ws_frame frame;
    int i, expect_size = 0;
    while (!TCP_CHAN_READ_BUF_EMPTY(peer->chan)) {
        if (peer->parse_buf->size < 2) {
            sbuf_appendc(peer->parse_buf, TCP_CHAN_READC(peer->chan));
        } else {
            char *p = peer->parse_buf->data;
            frame.fin = p[0] & 0x80;
            frame.opcode = p[0] & 0xf;
            frame.mask = p[1] & 0x80;
            frame.payload_len = p[1] & 0x7f;

            if (frame.payload_len == 126) {
                if (peer->parse_buf->size < 4) {
                    sbuf_appendc(peer->parse_buf, TCP_CHAN_READC(peer->chan));
                    continue;
                } else {
                    frame.payload_len = unpack_be16(peer->parse_buf->data + 2);
                    expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 4 - peer->parse_buf->size;
                }
            } else if (frame.payload_len == 127) {
                if (peer->parse_buf->size < 10) {
                    sbuf_appendc(peer->parse_buf, TCP_CHAN_READC(peer->chan));
                    continue;
                } else {
                    frame.payload_len = (int)unpack_be64(peer->parse_buf->data + 2);
                    expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 10 - peer->parse_buf->size;
                }
            } else {
                expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 2 - peer->parse_buf->size;
            }

            int old_size = peer->parse_buf->size;
            int buf_size = TCP_CHAN_GET_READ_BUF_SIZE(peer->chan);
            if (buf_size < expect_size) {
                sbuf_resize(peer->parse_buf, old_size + buf_size);
                TCP_CHAN_READ(peer->chan, peer->parse_buf->data + old_size, buf_size);
                break;
            }

            sbuf_resize(peer->parse_buf, old_size + expect_size);
            TCP_CHAN_READ(peer->chan, peer->parse_buf->data + old_size, expect_size);
            frame.payload_data = sbuf_tail(peer->parse_buf) - frame.payload_len;
            if (frame.mask) {
                memcpy(frame.mask_key, sbuf_tail(peer->parse_buf) - frame.payload_len - 4, 4);
                int i;
                for (i = 0; i < frame.payload_len; ++i)
                    frame.payload_data[i] ^= frame.mask_key[i % 4];
            }
            peer_ws_frame_handler(peer, &frame);
            sbuf_clear(peer->parse_buf);
        }
    }
}

void peer_data_handler(TCP_CHAN_T *chan, void *udata)
{
    http_peer_t *peer = udata;
    while (!TCP_CHAN_READ_BUF_EMPTY(chan)) {
        if (peer->upgraded) {
            peer_ws_data_handler(peer);
        } else {
            if (peer->parse_state == HTTP_PARSE_HEADER) {
                char c = TCP_CHAN_READC(chan);
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
                            http_request_handler(peer, req);
                            peer->parse_request = NULL;
                        }
                    } else {
                        send_final_reply(peer, HTTP_STATUS_BAD_REQUEST);
                    }
                }
            } else if (peer->parse_state == HTTP_PARSE_BODY) {
                if (peer->parse_request->body_len <= TCP_CHAN_GET_READ_BUF_SIZE(chan)) {
                    TCP_CHAN_READ(chan, peer->parse_request->body,
                                  peer->parse_request->body_len);
                    http_request_handler(peer, peer->parse_request);
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

void peer_error_handler(TCP_CHAN_T *chan, int status, void *udata)
{
    http_peer_t *peer = udata;
    http_peer_del(peer);
}

void send_final_reply(http_peer_t *peer, http_status_t status)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 %d %s\r\n"
                     "Connection:close\r\n"
                     "\r\n",
                     status, http_strstatus(status));
    if (n > 0) {
        TCP_CHAN_WRITE(peer->chan, s, n);
        free(s);
    }
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void send_json(http_peer_t *peer, cJSON *json)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *text = cJSON_PrintUnformatted(json);
    if (!text)
        return;
    send_ws_frame(peer, WS_OPCODE_TEXT, text, strlen(text));
    free(text);
}

void send_error(http_peer_t *peer, const char *session_id, const char *transaction,
                int error, const char *format, ...)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *error_string = NULL;
    char error_buf[512];
    if (!format) {
        /* No error string provided, use the default one */
        error_string = (char*)rtz_get_api_error(error);
    } else {
        /* This callback has variable arguments (error string) */
        va_list ap;
        va_start(ap, format);
        vsnprintf(error_buf, sizeof(error_buf), format, ap);
        va_end(ap);
        error_string = error_buf;
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "message");
    cJSON_AddStringToObject(json, "session_id", session_id);
    cJSON_AddStringToObject(json, "transaction", transaction);
    cJSON *error_json = cJSON_AddObjectToObject(json, "error");
    cJSON_AddNumberToObject(error_json, "code", error);
    cJSON_AddStringToObject(error_json, "reason", error_string);
    send_json(peer, json);
    cJSON_Delete(json);
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
        TCP_CHAN_WRITE(peer->chan, s, n);
        free(s);
    }
    sbuf_del(sec_key);
}

/** @brief Send websocket frame
 *  @param peer The upgraded peer.
 *  @param opcode The websocket opcode
 *  @param data The frame data.
 *  @param size The frame size.
 */
void send_ws_frame(http_peer_t *peer, int opcode, const void *data, int size)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    if (!peer->upgraded)
        return;

    char header[10];
    int n = 0;
    header[0] = 0x80 | (char)opcode;
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
    TCP_CHAN_WRITE(peer->chan, header, n);
    TCP_CHAN_WRITE(peer->chan, data, size);
}

void create_session(http_peer_t *peer, const char *transaction)
{
    rtz_session_t *session = malloc(sizeof(rtz_session_t));
    memset(session, 0, sizeof(rtz_session_t));
    session->srv = peer->srv;
    session->peer = peer;
    session->id = sbuf_random_string(12);
    INIT_LIST_HEAD(&session->handle_list);
    list_add(&session->link, &peer->srv->session_list);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "transaction", transaction);
    cJSON_AddStringToObject(json, "session_id", session->id->data);
    cJSON_AddStringToObject(json, "type", "success");
    send_json(peer, json);
    cJSON_Delete(json);

    LLOG(LL_TRACE, "create_session %p sid='%s'", session, session->id->data);
}

void destroy_session(http_peer_t *peer, const char *transaction, const char *session_id)
{
    rtz_session_t *session = find_session(peer->srv, session_id);
    LLOG(LL_TRACE, "destroy_session %p sid='%s'",
         session, session_id);
    if (!session) {
        send_error(peer, session_id, transaction, RTZ_ERROR_SESSION_NOT_FOUND, NULL);
        peer->flag |= HTTP_PEER_CLOSE_ASAP;
        return;
    }
    rtz_handle_t *h, *htmp;
    list_for_each_entry_safe(h, htmp, &session->handle_list, link) {
        destroy_handle(peer, NULL, session_id, h->id->data);
    }
    rtz_session_del(session);

    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "transaction", transaction);
    cJSON_AddStringToObject(json, "session_id", session_id);
    cJSON_AddStringToObject(json, "type", "success");
    send_json(peer, json);
    cJSON_Delete(json);
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void parse_url(rtz_handle_t *h, const char *url)
{
    sbuf_strcpy(h->url, url);
    const char *p = strchr(url + 7, '/');
    if (p) {
        const char *q1 = strchr(p + 1, '?');
        const char *q2 = strchr(p + 1, '/');
        const char *q;
        if (!q1)
            q = q2;
        else if (!q2)
            q = q1;
        else
            q = (q1 < q2) ? q1 : q2;
        if (q)
            sbuf_strncpy(h->app, p + 1, q - (p + 1));
        else
            sbuf_strcpy(h->app, p + 1);
    } else {
        sbuf_strcpy(h->app, "live");
    }
    p = strrchr(url, '/');
    if (p) {
        sbuf_strcpy(h->stream_name, p + 1);
        sbuf_strncpy(h->tc_url, url, p - url);
    } else {
        sbuf_strcpy(h->tc_url, url);
    }
    LLOG(LL_TRACE, "parse_url('%s'): app='%s' tcUrl='%s' streamName='%s'",
         url, h->app->data, h->tc_url->data, h->stream_name->data);
}

void create_handle(http_peer_t *peer, const char *transaction, const char *session_id,
                   const char *url, const char *transport, uint16_t min_playout_delay)
{
    rtz_session_t *session = find_session(peer->srv, session_id);
    int tcp = transport && !strcasecmp(transport, "tcp");
    if (!session) {
        //send_json_error(peer, -1, "Session not found");
        LLOG(LL_ERROR, "sid='%s' not found", session_id);
        return;
    }
    if (!url) {
        //send_json_error(peer, -1, "Session not found");
        LLOG(LL_ERROR, "sid='%s' url '%s' not valid", session_id, url ?: "<null>");
        return;
    }

    rtz_handle_t *handle = malloc(sizeof(rtz_handle_t));
    LLOG(LL_TRACE, "rtz_handle_new %p", handle);
    memset(handle, 0, sizeof(rtz_handle_t));
    handle->session = session;
    handle->id = sbuf_random_string(12);
    handle->url = sbuf_new();
    handle->app = sbuf_new();
    handle->tc_url = sbuf_new();
    handle->stream_name = sbuf_new();
    parse_url(handle, url);
    handle->stream = NULL;
    handle->min_playout_delay = min_playout_delay;
    handle->ice = ice_agent_new(peer->srv->ice_srv, handle);
    list_add(&handle->link, &session->handle_list);

    handle->stream = find_stream(peer->srv, handle->stream_name->data);
    if (handle->stream) {
        LLOG(LL_INFO, "handle %p join stream %p (name='%s')",
             handle, handle->stream, handle->stream_name->data);
        list_add(&handle->stream_link, &handle->stream->handle_list);
    }

    sbuf_t *offer_sdp = create_sdp(handle, tcp);
    handle->flag = RTZ_HANDLE_PREPARING;

    LLOG(LL_TRACE, "create_handle %p sid='%s' hid='%s'",
         handle, session_id, handle->id->data);

    {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "transaction", transaction);
        cJSON_AddStringToObject(json, "session_id", session_id);
        cJSON_AddStringToObject(json, "id", handle->id->data);
        cJSON_AddStringToObject(json, "type", "success");
        send_json(peer, json);
        cJSON_Delete(json);
    }

    cJSON* json = make_streaming_event(handle, "preparing", NULL);
    sbuf_t *txid = sbuf_random_string(12);
    cJSON_AddStringToObject(json, "transaction", txid->data);
    cJSON *jsep = cJSON_AddObjectToObject(json, "jsep");
    cJSON_AddStringToObject(jsep, "type", "offer");
    cJSON_AddStringToObject(jsep, "sdp", offer_sdp->data);
    send_json(peer, json);
    sbuf_del(txid);
    sbuf_del(offer_sdp);
    cJSON_Delete(json);
}

void destroy_handle(http_peer_t *peer, const char *transaction,
                    const char *session_id, const char *handle_id)
{
    rtz_handle_t *handle = find_handle(peer->srv, session_id, handle_id);
    LLOG(LL_TRACE, "destroy_handle %p sid='%s' hid='%s'",
         handle, session_id, handle_id);
    if (handle) {
        {
            cJSON *json = cJSON_CreateObject();
            cJSON_AddStringToObject(json, "type", "destroyed");
            cJSON_AddStringToObject(json, "session_id", session_id);
            cJSON_AddStringToObject(json, "sender", handle_id);
            send_json(peer, json);
            cJSON_Delete(json);
        }
        rtz_handle_del(handle);
    }

    if (transaction) {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "transaction", transaction);
        cJSON_AddStringToObject(json, "session_id", session_id);
        cJSON_AddStringToObject(json, "type", "success");
        send_json(peer, json);
        cJSON_Delete(json);
    }
}

void handle_message(http_peer_t *peer, const char *transaction,
                    const char *session_id, const char *handle_id,
                    cJSON *body, cJSON *jsep)
{
    const char *request = cJSON_GetStringValue(cJSON_GetObjectItem(body, "request"));
    const char *stream_name = cJSON_GetStringValue(cJSON_GetObjectItem(body, "stream"));
    if (!strcmp(request, "start")) {
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(jsep, "type"));
        const char *sdp = cJSON_GetStringValue(cJSON_GetObjectItem(jsep, "sdp"));
        assert(!strcmp(type, "answer"));
        process_sdp_answer(peer, transaction, session_id, handle_id, sdp);
    } else {
        LLOG(LL_WARN, "unhandled type='message' request='%s' body='%s' jsep='%s'",
             request, cJSON_PrintUnformatted(body), jsep ? cJSON_PrintUnformatted(jsep) : "");
        //stop_stream(peer, transaction, session_id, handle_id);
    }
}

sbuf_t * create_sdp(rtz_handle_t *handle, int tcp)
{
    ice_agent_t *agent = handle->ice;
    const char *user = ice_get_luser(agent);
    const char *pwd = ice_get_lpass(agent);
    const char *fingerprint = dtls_get_local_fingerprint();
    uint32_t audio_ssrc = ice_get_ssrc(agent, 0);
    uint32_t video_ssrc = ice_get_ssrc(agent, 1);

    sbuf_t *sdp = sbuf_newf(
        "v=0\r\n"
        "o=- 1550110455648463 %d IN IP4 %s\r\n"
        "s=%s\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE audio video\r\n"
        "a=msid-semantic: WMS rtz\r\n"
        "a=ice-lite\r\n",
        ++handle->sdp_version,
        RTZ_PUBLIC_IP, handle->stream_name->data);

    ice_flags_set(agent, ICE_HANDLE_WEBRTC_HAS_AUDIO);
    sbuf_appendf(
        sdp,
        "m=audio 9 UDP/TLS/RTP/SAVPF 8\r\n"
        "c=IN IP4 %s\r\n"
        "a=sendonly\r\n"
        "a=mid:audio\r\n"
        "a=rtcp-mux\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:actpass\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        //"a=maxptime:40\r\n"
        "a=fmtp:8 \r\n"
        "a=ssrc:%"SCNu32" cname:rtzaudio\r\n"
        "a=ssrc:%"SCNu32" msid:rtz rtza0\r\n"
        "a=ssrc:%"SCNu32" mslabel:rtz\r\n"
        "a=ssrc:%"SCNu32" label:rtza0\r\n",
        RTZ_PUBLIC_IP, user, pwd, fingerprint,
        audio_ssrc, audio_ssrc, audio_ssrc, audio_ssrc);
    if (tcp)
        sbuf_appendf(
            sdp,
            "a=candidate:1 1 tcp 2013266431 %s %d typ host tcptype passive\r\n"
            "a=end-of-candidates\r\n",
            RTZ_PUBLIC_IP, RTZ_PUBLIC_MEDIA_PORT);
    else
        sbuf_appendf(
            sdp,
            "a=candidate:1 1 udp 2013266431 %s %d typ host\r\n"
            "a=end-of-candidates\r\n",
            RTZ_PUBLIC_IP, RTZ_PUBLIC_MEDIA_PORT);

    ice_flags_set(agent, ICE_HANDLE_WEBRTC_HAS_VIDEO);
    sbuf_appendf(
        sdp,
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
        "c=IN IP4 %s\r\n"
        "a=sendonly\r\n"
        "a=mid:video\r\n"
        "a=rtcp-mux\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:actpass\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        /* below line not compatible with Firefox */
        //"a=fmtp:96 profile-level-id=420029; packetization-mode=1; sprop-parameter-sets=Z00AKp2oHgCJ+WbgICAoAAADAAgAAAMBlCA=,aO48gA==\r\n"
        "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\r\n"
        "a=rtcp-fb:96 nack\r\n"
        "a=rtcp-fb:96 nack pli\r\n"
        "a=rtcp-fb:96 goog-remb\r\n"
        "a=ssrc:%"SCNu32" cname:rtzvideo\r\n"
        "a=ssrc:%"SCNu32" msid:rtz rtzv0\r\n"
        "a=ssrc:%"SCNu32" mslabel:rtz\r\n"
        "a=ssrc:%"SCNu32" label:rtzv0\r\n",
        RTZ_PUBLIC_IP, user, pwd, fingerprint,
        video_ssrc, video_ssrc, video_ssrc, video_ssrc);
    sbuf_appendf(
        sdp,
        "a=extmap:6 %s\r\n",
        RTZ_RTP_EXTMAP_PLAYOUT_DELAY);
    if (tcp)
        sbuf_appendf(
            sdp,
            "a=candidate:1 1 tcp 2013266431 %s %d typ host tcptype passive\r\n"
            "a=end-of-candidates\r\n",
            RTZ_PUBLIC_IP, RTZ_PUBLIC_MEDIA_PORT);
    else
        sbuf_appendf(
            sdp,
            "a=candidate:1 1 udp 2013266431 %s %d typ host\r\n"
            "a=end-of-candidates\r\n",
            RTZ_PUBLIC_IP, RTZ_PUBLIC_MEDIA_PORT);

    return sdp;
}

rtz_session_t *find_session(rtz_server_t *srv, const char *session_id)
{
    rtz_session_t *s;
    list_for_each_entry(s, &srv->session_list, link) {
        if (!strcmp(s->id->data, session_id))
            return s;
    }
    return NULL;
}

rtz_handle_t *find_handle(rtz_server_t *srv, const char *session_id,
                          const char *handle_id)
{
    rtz_session_t *session;
    list_for_each_entry(session, &srv->session_list, link) {
        if (!strcmp(session->id->data, session_id)) {
            rtz_handle_t *stream;
            list_for_each_entry(stream, &session->handle_list, link) {
                if (!strcmp(stream->id->data, handle_id))
                    return stream;
            }
        }
    }
    return NULL;
}

rtz_stream_t *find_stream(rtz_server_t *srv, const char *stream_name)
{
    rtz_stream_t *s;
    list_for_each_entry(s, &srv->stream_list, link) {
        if (!strcmp(s->stream_name->data, stream_name))
            return s;
    }
    return NULL;
}

void process_sdp_answer(http_peer_t *peer, const char *transaction,
                        const char *session_id, const char *handle_id,
                        const char *sdp)
{
    /*
    LLOG(LL_TRACE, "process_sdp_answer txid='%s' sid='%s' hid='%s' sdp='%s'",
         transaction, session_id, handle_id, sdp);
    */
    rtz_handle_t *handle = find_handle(peer->srv, session_id, handle_id);
    LLOG(LL_TRACE, "process_sdp_answer handle %p sid='%s' hid='%s'",
         handle, session_id, handle_id);
    if (!handle) {
        //send_json_error(peer, -1, "Session not found");
        LLOG(LL_ERROR, "sid='%s' hid='%s' not found", session_id, handle_id);
        return;
    }
    ice_stream_t *ice_stream = ice_get_stream(handle->ice);
    const char *p;
    char *rhash, *rfingerprint, *rpass;
    int ret;
    p = strstr(sdp, "a=fingerprint:");
    assert(p);
    ret = sscanf(p, "a=fingerprint: %ms %ms", &rhash, &rfingerprint);
    assert(ret == 2);
    sbuf_strcpy(ice_stream_get_remote_hashing(ice_stream), rhash);
    sbuf_strcpy(ice_stream_get_remote_fingerprint(ice_stream), rfingerprint);

    p = strstr(sdp, "a=ice-pwd:");
    if (p) {
        assert(p);
        ret = sscanf(p, "a=ice-pwd: %ms", &rpass);
        assert(ret == 1);
        sbuf_strcpy(ice_get_rpass(handle->ice), rpass);
        free(rpass);
    }

    //LLOG(LL_TRACE, "rpass=%s rhash=%s rfingerprint=%s", rpass, rhash, rfingerprint);

    free(rhash);
    free(rfingerprint);

    handle->flag = RTZ_HANDLE_STARTING;
    cJSON* json = make_streaming_event(handle, "starting", NULL);
    send_json(handle->session->peer, json);
    cJSON_Delete(json);
}

void send_rtp(rtz_handle_t *handle, int video, const void *data, int size)
{
    if (!handle->ice || ice_flags_is_set(handle->ice, ICE_HANDLE_WEBRTC_STOP)
        || ice_flags_is_set(handle->ice, ICE_HANDLE_WEBRTC_ALERT))
        return;
    ice_send_rtp(handle->ice, video, data, size);
}

rtz_stream_t *rtz_stream_new(rtz_server_t *srv, const char *stream_name)
{
    rtz_stream_t *stream = malloc(sizeof(rtz_stream_t));
    LLOG(LL_INFO, "rtz_stream_new %p (name=%s)", stream, stream_name);
    stream->srv = srv;
    stream->stream_name = sbuf_strdup(stream_name);
    stream->rtp_mux = rtp_mux_new();
    rtp_mux_set_cb(stream->rtp_mux, rtp_mux_handler, stream);
    list_add_tail(&stream->link, &srv->stream_list);
    INIT_LIST_HEAD(&stream->handle_list);

    rtz_session_t *session;
    rtz_handle_t *handle;
    list_for_each_entry(session, &srv->session_list, link) {
        list_for_each_entry(handle, &session->handle_list, link) {
            if (!strcmp(handle->stream_name->data, stream_name)) {
                LLOG(LL_INFO, "handle %p join stream %p (name='%s')", handle, stream, stream_name);
                handle->stream = stream;
                list_add(&handle->stream_link, &stream->handle_list);
            }
        }
    }
#if ENABLE_RTP_TESTCHAN
    stream->test_chan = udp_chan_new(srv->loop);
#endif
    return stream;
}

void rtz_stream_del(rtz_stream_t *stream)
{
    LLOG(LL_INFO, "rtz_stream_del %p (name=%s)", stream, stream->stream_name->data);
    rtz_handle_t *h, *tmp;
    list_for_each_entry_safe(h, tmp, &stream->handle_list, stream_link) {
        h->stream = NULL;
        list_del(&h->stream_link);
        if (h->ice) {
            {
                cJSON *json = cJSON_CreateObject();
                cJSON_AddStringToObject(json, "type", "destroyed");
                cJSON_AddStringToObject(json, "session_id", h->session->id->data);
                cJSON_AddStringToObject(json, "sender", h->id->data);
                send_json(h->session->peer, json);
                cJSON_Delete(json);
            }
            ice_webrtc_hangup(h->ice, "UnPublish");
            rtz_handle_del(h);
        }
    }
    INIT_LIST_HEAD(&stream->handle_list);
    list_del(&stream->link);
    sbuf_del(stream->stream_name);
    rtp_mux_del(stream->rtp_mux);
    free(stream);
}

rtz_stream_t *rtz_stream_get(rtz_server_t *srv, const char *stream_name)
{
    return find_stream(srv, stream_name);
}

void rtz_stream_set_video_codec_h264(rtz_stream_t *stream, const void *data, int size)
{
    const uint8_t *p = data;
    uint8_t num_sps = p[5] & 0x1f;
    uint16_t sps_size = unpack_be16(p + 6);
    const uint8_t *sps_data = p + 8;
    uint8_t num_pps = p[8 + sps_size];
    uint16_t pps_size = unpack_be16(p + 8 + sps_size + 1);
    const uint8_t *pps_data = p + 8 + sps_size + 3;
    rtp_mux_set_sps_pps(stream->rtp_mux, sps_data, sps_size,
                        pps_data, pps_size);
}

void rtz_stream_push_video(rtz_stream_t *stream, uint32_t rtp_ts, uint16_t sframe_time,
                           int key_frame, const void *data, int size)
{
    stream->last_time = zl_time();
    stream->sframe_time = sframe_time;
    rtp_mux_input(stream->rtp_mux, 1, rtp_ts, data, size);
}

void rtz_stream_push_audio(rtz_stream_t *stream, uint32_t rtp_ts, const void *data, int size)
{
    rtp_mux_input(stream->rtp_mux, 0, rtp_ts, data, size);
}

void rtz_stream_update_videotime(rtz_stream_t *stream, double videotime)
{
    rtz_handle_t *h, *tmp;
    list_for_each_entry_safe(h, tmp, &stream->handle_list, stream_link) {
        if (!(h->flag & RTZ_HANDLE_STARTED))
            continue;
        cJSON *result;
        cJSON *json = make_streaming_event(h, "progress", &result);
        cJSON_AddNumberToObject(result, "videotime", videotime);
        send_json(h->session->peer, json);
        cJSON_Delete(json);
    }
}

void rtz_webrtcup(void *rtz_handle)
{
    //LLOG(LL_TRACE, "rtz_webrtcup");
    rtz_handle_t *handle = rtz_handle;
    if (!handle)
        return;
    rtz_session_t *session = handle->session;
    if (!session)
        return;

    handle->flag = RTZ_HANDLE_RTC_UP;

    {
        cJSON *json = cJSON_CreateObject();
        cJSON_AddStringToObject(json, "type", "webrtcup");
        cJSON_AddStringToObject(json, "sender", handle->id->data);
        send_json(session->peer, json);
        cJSON_Delete(json);
    }
}

static void ice_agent_defer_del(zl_loop_t* loop, int64_t status, void *udata)
{
    ice_agent_t *agent = udata;
    ice_agent_del(agent);
}

void rtz_hangup(void *rtz_handle)
{
    rtz_handle_t *handle = rtz_handle;
    LLOG(LL_WARN, "rtz_hangup %p ice_agent=%p", rtz_handle, handle->ice);
    if (handle->ice) {
        //LLOG(LL_WARN, "defer del ice_agent %p", handle->ice);
        zl_defer(handle->session->srv->loop, ice_agent_defer_del, 0, handle->ice);
        handle->ice = NULL;
    }
}

int rtz_get_server_load(rtz_server_t *srv)
{
    if (!srv)
        return 0;
    int load = 0;
    rtz_stream_t *stream;
    list_for_each_entry(stream, &srv->stream_list, link) {
        ++load;
    }
    rtz_session_t *session;
    rtz_handle_t *handle;
    list_for_each_entry(session, &srv->session_list, link) {
        list_for_each_entry(handle, &session->handle_list, link) {
            ++load;
        }
    }
    return load;
}

/* Write 12 bit min_playout_delay in 10ms granularity */
static inline void update_playout_delay_ext(uint8_t *ext, uint16_t min_delay)
{
    uint16_t d = min_delay / 10;
    ext[1] = (d >> 4) & 0xff;
    ext[2] = ((d << 4) & 0xf0) | (ext[2] & 0x0f);
}

void rtp_mux_handler(int video, int kf, void *data, int size, void *udata)
{
    rtz_stream_t *stream = udata;
    rtz_handle_t *handle, *tmp;
    uint8_t *playout_delay_ext_ref = NULL;
    if (video && kf) {
        /* Check playout-delay extension */
        rtp_header_extension_find(data, size, 6, NULL, NULL, (char**)&playout_delay_ext_ref);
    }
    list_for_each_entry_safe(handle, tmp, &stream->handle_list, stream_link) {
        if (video && kf && (handle->flag & RTZ_HANDLE_RTC_UP)) {
            /* Check to send 'started' streaming event */
            handle->flag = RTZ_HANDLE_STARTED;
            cJSON* json = make_streaming_event(handle, "started", NULL);
            send_json(handle->session->peer, json);
            cJSON_Delete(json);
        }
        if (playout_delay_ext_ref) {
            const uint16_t frame_time = stream->sframe_time ?: 40;
            update_playout_delay_ext(playout_delay_ext_ref,
                                     frame_time * handle->min_playout_delay);
            ice_prepare_video_keyframe(handle->ice);
        }
        send_rtp(handle, video, data, size);
    }

#ifdef ENABLE_RTP_TESTCHAN
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12340);
    inet_pton(AF_INET, "172.20.226.53", &addr.sin_addr);
    udp_chan_write(stream->test_chan, data, size,
        (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
#endif
}

void rtz_handle_del(rtz_handle_t *handle)
{
    LLOG(LL_TRACE, "rtz_handle_del %p", handle);
    /* Leave publish stream */
    if (handle->stream) {
        LLOG(LL_INFO, "handle %p leave stream %p (name='%s')",
             handle, handle->stream, handle->stream_name->data);
        list_del(&handle->stream_link);
        handle->stream = NULL;
    }
    /* hangup the PeerConnection, if any */
    if (handle->ice) {
        ice_flags_set(handle->ice, ICE_HANDLE_WEBRTC_STOP);
        ice_webrtc_hangup(handle->ice, "DestroyHandle");
        handle->ice = NULL;
    }
    list_del(&handle->link);
    sbuf_del(handle->stream_name);
    sbuf_del(handle->url);
    sbuf_del(handle->app);
    sbuf_del(handle->tc_url);
    sbuf_del(handle->id);
    free(handle);
}

void rtz_session_del(rtz_session_t *session)
{
    rtz_handle_t *h, *htmp;
    list_for_each_entry_safe(h, htmp, &session->handle_list, link) {
        rtz_handle_del(h);
    }
    list_del(&session->link);
    sbuf_del(session->id);
    free(session);
}

void rtz_get_stream_info(rtz_server_t *srv, const char *stream_name, int *num_publisher, int *num_player)
{
    rtz_stream_t *stream;
    rtz_session_t *session, *stmp;
    rtz_handle_t *handle, *htmp;

    *num_publisher = 0;
    list_for_each_entry(stream, &srv->stream_list, link) {
        if (!strcmp(stream->stream_name->data, stream_name)) {
            *num_publisher = 1;
            break;
        }
    }

    *num_player = 0;
    if (*num_publisher > 0) {
        /* Count player in publishing stream's own list */
        list_for_each_entry_safe(handle, htmp, &stream->handle_list, stream_link) {
            if (!strcmp(handle->stream_name->data, stream_name)) {
                ++*num_player;
            }
        }
    } else {
        /* Count player in every rtz_session and rtz_handle */
        list_for_each_entry_safe(session, stmp, &srv->session_list, link) {
            list_for_each_entry_safe(handle, htmp, &session->handle_list, link) {
                if (!strcmp(handle->stream_name->data, stream_name)) {
                    ++*num_player;
                }
            }
        }
    }
}

cJSON *make_streaming_event(rtz_handle_t *handle, const char *ename, cJSON **presult)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "event");
    cJSON_AddStringToObject(json, "session_id", handle->session->id->data);
    cJSON_AddStringToObject(json, "sender", handle->id->data);
    cJSON *data = cJSON_AddObjectToObject(json, "data");
    {
        cJSON_AddStringToObject(data, "streaming", "event");
        cJSON *result = cJSON_AddObjectToObject(data, "result");
        {
            cJSON_AddStringToObject(result, "status", ename);
        }
        if (presult)
            *presult = result;
    }
    return json;
}
