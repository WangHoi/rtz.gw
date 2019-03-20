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

extern const char *RTZ_LOCAL_IP;
const char *HTTP_HOOKS_URL = "http://172.16.3.101:10001/streamcloud-control-service/srs/appgw/auth";

struct http_hook_ctx {
    zl_loop_t *loop;
    tcp_chan_t *chan;
    int timer;

    sbuf_t *response_buf;

    sbuf_t *app;
    sbuf_t *tc_url;
    sbuf_t *stream_name;
    sbuf_t *action;
    http_hook_cb func;
    void *udata;
};

static void http_fd_read_handler(tcp_chan_t *chan, void *udata);
static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata);
static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata);
static int parse_url(const char *url, char *ip, unsigned *port);
static void timeout_handler(zl_loop_t *loop, int id, void *udata);
static void http_hook_ctx_del(struct http_hook_ctx *ctx);

void http_hook_query(zl_loop_t *loop, const char *app, const char *tc_url,
                     const char *stream_name, const char *action,
                     http_hook_cb func, void *udata)
{
    char ip[128];
    unsigned port;
    if (parse_url(HTTP_HOOKS_URL, ip, &port)) {
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
    ctx->timer = zl_timer_start(loop, 3000, 0, timeout_handler, ctx);
    ctx->response_buf = sbuf_new1(1024);
    ctx->app = sbuf_strdup(app);
    ctx->stream_name = sbuf_strdup(stream_name);
    ctx->tc_url = sbuf_strdup(tc_url);
    ctx->action = sbuf_strdup(action);
    ctx->func = func;
    ctx->udata = udata;
}

void http_fd_read_handler(tcp_chan_t *chan, void *udata)
{
    struct http_hook_ctx *ctx = udata;
    int rlen = tcp_chan_get_read_buf_size(chan);
    sbuf_resize(ctx->response_buf, ctx->response_buf->size + rlen);
    tcp_chan_read(chan, sbuf_tail(ctx->response_buf), rlen);
    char *rend = strstr(ctx->response_buf->data, "\r\n\r\n");
    int finished = 0;
    if (rend) {
        rend += 4;
        http_response_t *r = http_parse_response(ctx, ctx->response_buf->data, rend);
        if (r && rend + r->body_len == sbuf_tail(ctx->response_buf)) {
            cJSON *json = cJSON_Parse(rend);
            if (json) {
                cJSON *code_node = cJSON_GetObjectItem(json, "code");
                const char *msg = cJSON_GetStringValue(cJSON_GetObjectItem(json, "data")) ? : "";
                int code = cJSON_IsNumber(code_node) ? code_node->valueint : -3;
                if (ctx->func)
                    ctx->func(ctx->loop, ctx->app->data, ctx->tc_url->data,
                              ctx->stream_name->data, ctx->action->data, code, ctx->udata);
                finished = 1;
            }
        }
        free(r);
    }
    if (finished)
        http_hook_ctx_del(ctx);
}

static void http_hook_ctx_del(struct http_hook_ctx *ctx)
{
    zl_timer_stop(ctx->loop, ctx->timer);
    tcp_chan_close(ctx->chan, 0);
    sbuf_del(ctx->app);
    sbuf_del(ctx->tc_url);
    sbuf_del(ctx->stream_name);
    sbuf_del(ctx->response_buf);
    sbuf_del(ctx->action);
    free(ctx);
}

static void http_fd_event_handler(tcp_chan_t *chan, int status, void *udata)
{
    LLOG(LL_TRACE, "http event %d", status);
    struct http_hook_ctx *ctx = udata;
    if (status > 0) {
        /* Connected, send request */
        char *body = NULL;
        UNUSED(asprintf(&body, "{ \"action\":\"%s\",\"client_id\" : 1242,"
                 "\"ip\" : \"%s\",\"vhost\" : \"__defaultVhost__\",\"app\" : \"%s\","
                 "\"tcUrl\" : \"%s\","
                 "\"pageUrl\" : \"\" };", ctx->action->data,
                 RTZ_LOCAL_IP, ctx->app->data, ctx->tc_url->data));
        if (body) {
            sbuf_t *request = sbuf_newf(
                "POST /streamcloud-control-service/srs/appgw/auth\r\n"
                "Host:172.20.226.86\r\n"
                "Connection:close\r\n"
                "Content-Type:application/json\r\n"
                "Content-Length:%zd\r\n"
                "\r\n", strlen(body));
            sbuf_append1(request, body);
            free(body);
            tcp_chan_write(chan, request->data, request->size);
        }
        return;
    }

    if (status == 0) {
        int rlen = tcp_chan_get_read_buf_size(chan);
        sbuf_resize(ctx->response_buf, ctx->response_buf->size + rlen);
        tcp_chan_read(chan, sbuf_tail(ctx->response_buf), rlen);
        char *rend = strstr(ctx->response_buf->data, "\r\n\r\n");
        if (rend) {
            rend += 4;
            http_response_t *r = http_parse_response(ctx, ctx->response_buf->data, rend);
            if (r && rend + r->body_len == sbuf_tail(ctx->response_buf)) {
                cJSON *json = cJSON_Parse(rend);
                if (json) {
                    cJSON *code_node = cJSON_GetObjectItem(json, "code");
                    const char *msg = cJSON_GetStringValue(cJSON_GetObjectItem(json, "data")) ?: "";
                    int code = cJSON_IsNumber(code_node) ? code_node->valueint : -3;
                    if (ctx->func)
                        ctx->func(ctx->loop, ctx->app->data, ctx->tc_url->data,
                                    ctx->stream_name->data, ctx->action->data, code, ctx->udata);
                }
            }
            free(r);
        }
    } else {
        if (ctx->func)
            ctx->func(ctx->loop, ctx->app->data, ctx->tc_url->data,
                      ctx->stream_name->data, ctx->action->data, status, ctx->udata);
    }
    http_hook_ctx_del(ctx);
}

int parse_url(const char *url, char *ip, unsigned *port)
{
    const char *p = strchr(url + 7, ':');
    if (!p)
        return -1;
    if (p - (url + 7) > 32)
        return -2;
    memcpy(ip, url + 7, p - (url + 7));
    ip[p - (url + 7)] = 0;
    *port = atoi(p + 1);
    LLOG(LL_TRACE, "ip='%s' port=%u", ip, *port);
    return 0;
}

void timeout_handler(zl_loop_t *loop, int id, void *udata)
{
    struct http_hook_ctx *ctx = udata;
    if (ctx->func)
        ctx->func(ctx->loop, ctx->app->data, ctx->tc_url->data,
                  ctx->stream_name->data, ctx->action->data, -2, "Timeout Error");
    http_hook_ctx_del(ctx);
}
