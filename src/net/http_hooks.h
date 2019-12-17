/** @file http_hooks.h
 *  HTTP client of stream authorization hooks.
 */
#pragma once

/** Error codes
 * @sa SRS流媒体服务器接口文档.doc #2.3
 */
enum {
    HTTP_HOOK_OK = 1,
    HTTP_HOOK_ILLEGAL_CONNECTION = -104,
    HTTP_HOOK_INVALID_ARGUMENT = -102,
    HTTP_HOOK_MISSING_ARGUMENT = -101,
    HTTP_HOOK_INTERNAL_ERROR = -100,
    HTTP_HOOK_TIMEOUT_ERROR = -504,
};

typedef struct zl_loop_t zl_loop_t;
typedef void (*http_hook_cb)(zl_loop_t *loop, long client_id, int result, void *udata);
void http_hook_on_play(zl_loop_t *loop, const char *app, const char *tc_url,
                       const char *stream_name, long client_id,
                       http_hook_cb func, void *udata);
/** @brief 流量上报
 *
 * 定时上报链路的流量，默认1小时上报一次，流量为1小时内产生的流量
 */
void http_hook_on_timer_report(zl_loop_t *loop, const char *app, const char *tc_url, const char *stream_name,
    long recv_bytes, long send_bytes, long client_id);
void http_hook_on_stop(zl_loop_t *loop, const char *app, const char *tc_url, const char *stream_name, long client_id);
void http_hook_on_close(zl_loop_t *loop, const char *app, const char *tc_url,
                        const char *stream_name, long recv_bytes, long send_bytes, long client_id);

