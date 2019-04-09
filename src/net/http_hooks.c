#include "http_hooks.h"
#include "event_loop.h"
#include "tcp_chan.h"
#include "log.h"
#include "sbuf.h"
#include "macro_util.h"
#include "net/http_types.h"
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>

enum {
    HTTP_HOOK_TIMEOUT_MSECS = 5000,
};

extern const char *RTZ_LOCAL_IP;
extern const char *HTTP_HOOKS_URL;

struct http_hook_ctx {
    zl_loop_t *loop;
    tcp_chan_t *chan;
    int timer;

    sbuf_t *response_buf;
    const char *path; /* const reference, DO NOT free */
    sbuf_t *body;
    long client_id;
    http_hook_cb func;
    void *udata;
};

static void http_fd_read_handler(tcp_chan_t *chan, void *udata);
static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata);
static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata);
static int parse_url(const char *url, char *ip, unsigned *port, const char **path);
static void timeout_handler(zl_loop_t *loop, int id, void *udata);
static void http_hook_ctx_del(struct http_hook_ctx *ctx);
static void http_hook_query(zl_loop_t *loop, const char *body,
                            long client_id, http_hook_cb func, void *udata);

void http_hook_query(zl_loop_t *loop, const char *body,
                     long client_id, http_hook_cb func, void *udata)
{
    if (!HTTP_HOOKS_URL)
        return;
    char ip[128];
    unsigned port;
    const char *path;
    if (parse_url(HTTP_HOOKS_URL, ip, &port, &path)) {
        LLOG(LL_ERROR, "parse url '%s' failed.", HTTP_HOOKS_URL);
        return;
    }
    struct http_hook_ctx *ctx = malloc(sizeof(struct http_hook_ctx));
    memset(ctx, 0, sizeof(struct http_hook_ctx));
    ctx->chan = tcp_connect(loop, ip, port);
    if (!ctx->chan) {
        LLOG(LL_ERROR, "connect to %s:%u error", ip, port);
        free(ctx);
        return;
    }
    tcp_chan_set_cb(ctx->chan, http_fd_read_handler, NULL, http_fd_event_handler, ctx);
    ctx->loop = loop;
    ctx->timer = zl_timer_start(loop, HTTP_HOOK_TIMEOUT_MSECS, 0, timeout_handler, ctx);
    ctx->response_buf = sbuf_new1(1024);
    ctx->path = path;
    ctx->body = sbuf_strdup(body);
    ctx->client_id = client_id;
    ctx->func = func;
    ctx->udata = udata;
}

void http_fd_read_handler(tcp_chan_t *chan, void *udata)
{
    struct http_hook_ctx *ctx = udata;
    int rlen = tcp_chan_get_read_buf_size(chan);
    int olen = ctx->response_buf->size;
    sbuf_resize(ctx->response_buf, olen + rlen);
    tcp_chan_read(chan, ctx->response_buf->data + olen, rlen);
    char *rend = strstr(ctx->response_buf->data, "\r\n\r\n");
    int finished = 0;
    if (rend) {
        rend += 4;
        http_response_t *r = http_parse_response(ctx, ctx->response_buf->data, rend);
        if (r && rend + r->body_len == sbuf_tail(ctx->response_buf)) {
            //LLOG(LL_TRACE, "recv '%s'", ctx->response_buf->data);
            cJSON *json = cJSON_Parse(rend);
            if (json) {
                cJSON *code_node = cJSON_GetObjectItem(json, "code");
                const char *msg = cJSON_GetStringValue(cJSON_GetObjectItem(json, "data")) ? : "";
                int code = cJSON_IsNumber(code_node) ? code_node->valueint : -3;
                cJSON_Delete(json);
                if (ctx->func)
                    ctx->func(ctx->loop, ctx->client_id, code, ctx->udata);
                finished = 1;
            }
        }
        http_response_del(r);
    }
    if (finished)
        http_hook_ctx_del(ctx);
}

static void http_hook_ctx_del(struct http_hook_ctx *ctx)
{
    zl_timer_stop(ctx->loop, ctx->timer);
    tcp_chan_close(ctx->chan, 0);
    sbuf_del(ctx->response_buf);
    sbuf_del(ctx->body);
    free(ctx);
}

static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata)
{
    //LLOG(LL_DEBUG, "http event %d", status);
    struct http_hook_ctx *ctx = udata;
    if (status > 0) {
        /* Connected, send request */
        sbuf_t *request = sbuf_newf(
            "POST %s HTTP/1.1\r\n"
            "Host:%s\r\n"
            "Connection:close\r\n"
            "Content-Type:application/json\r\n"
            "Content-Length:%d\r\n"
            "\r\n", ctx->path, RTZ_LOCAL_IP, ctx->body->size);
        sbuf_append(request, ctx->body);
        //LLOG(LL_DEBUG, "send '%s'", request->data);
        tcp_chan_write(chan, request->data, request->size);
        sbuf_del(request);
        return;
    }

    if (status == 0) {
        /* EOF */
        int rlen = tcp_chan_get_read_buf_size(chan);
        int olen = ctx->response_buf->size;
        sbuf_resize(ctx->response_buf, olen + rlen);
        tcp_chan_read(chan, ctx->response_buf->data + olen, rlen);
        //LLOG(LL_TRACE, "recv '%s'", ctx->response_buf->data);
        char *rend = strstr(ctx->response_buf->data, "\r\n\r\n");
        if (rend) {
            rend += 4;
            http_response_t *r = http_parse_response(ctx, ctx->response_buf->data, rend);
            if (r && rend + r->body_len == sbuf_tail(ctx->response_buf)) {
                cJSON *json = cJSON_Parse(rend);
                if (json) {
                    cJSON *code_node = cJSON_GetObjectItem(json, "code");
                    const char *msg = cJSON_GetStringValue(cJSON_GetObjectItem(json, "data")) ? : "";
                    int code = cJSON_IsNumber(code_node) ? code_node->valueint : -3;
                    cJSON_Delete(json);
                    if (ctx->func)
                        ctx->func(ctx->loop, ctx->client_id, code, ctx->udata);
                }
            }
            http_response_del(r);
        }
    } else {
        LLOG(LL_WARN, "http_hook client_id=%ld socket error.", ctx->client_id);
        if (ctx->func)
            ctx->func(ctx->loop, ctx->client_id, HTTP_HOOK_OK, ctx->udata);
    }
    http_hook_ctx_del(ctx);
}

int parse_url(const char *url, char *ip, unsigned *port, const char **path)
{
    const char *p = strchr(url + 7, ':');
    if (!p)
        return -1;
    if (p - (url + 7) > 32)
        return -2;
    memcpy(ip, url + 7, p - (url + 7));
    ip[p - (url + 7)] = 0;
    *port = atoi(p + 1);
    *path = strchr(p + 1, '/');
    //LLOG(LL_DEBUG, "ip='%s' port=%u path=%s", ip, *port, *path);
    return 0;
}

void timeout_handler(zl_loop_t *loop, int id, void *udata)
{
    struct http_hook_ctx *ctx = udata;
    if (ctx->func)
        ctx->func(ctx->loop, ctx->client_id, HTTP_HOOK_TIMEOUT_ERROR, ctx->udata);
    http_hook_ctx_del(ctx);
}


void http_hook_on_play(zl_loop_t *loop, const char *app, const char *tc_url, const char *stream_name,
                       long client_id, http_hook_cb func, void *udata)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "{"
             "\"action\":\"on_play\","
             "\"client_id\":\"%ld\","
             "\"ip\": \"%s\","
             "\"vhost\":\"__defaultVhost__\","
             "\"app\":\"%s\","
             "\"stream\":\"%s\","
             "\"tcUrl\":\"%s\","
             "\"pageUrl\":\"\"}", client_id, RTZ_LOCAL_IP, app, stream_name, tc_url);
    http_hook_query(loop, buf, client_id, func, udata);
}

void http_hook_on_stop(zl_loop_t *loop, const char *app, const char *tc_url,
                       const char *stream_name, long client_id)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "{"
             "\"action\":\"on_stop\","
             "\"client_id\":\"%ld\","
             "\"ip\": \"%s\","
             "\"vhost\":\"__defaultVhost__\","
             "\"app\":\"%s\","
             "\"tcUrl\":\"%s\","
             "\"stream\":\"%s\"}", client_id, RTZ_LOCAL_IP, app, tc_url, stream_name);
    http_hook_query(loop, buf, 0, NULL, NULL);
}

void http_hook_on_close(zl_loop_t *loop, const char *app, const char *tc_url,
                        const char *stream_name, long recv_bytes, long send_bytes, long client_id)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), "{"
             "\"action\":\"on_close\","
             "\"client_id\":\"%ld\","
             "\"ip\": \"%s\","
             "\"vhost\":\"__defaultVhost__\","
             "\"app\":\"%s\","
             "\"tcUrl\":\"%s\","
             "\"stream\":\"%s\","
             "\"send_bytes\":%ld,"
             "\"recv_bytes\":%ld,"
             "\"clientType\":\"play\"}", client_id,
             RTZ_LOCAL_IP, app, tc_url, stream_name, send_bytes, recv_bytes);
    http_hook_query(loop, buf, 0, NULL, NULL);
}
