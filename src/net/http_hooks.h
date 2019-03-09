/** @file http_hooks.h
 *  HTTP client of stream authorization hooks.
 */
#pragma once

typedef struct zl_loop_t zl_loop_t;
typedef void (*http_hook_cb)(zl_loop_t *loop, const char *app, const char *tc_url,
                             const char *stream_name, const char *action,
                             int result, void *udata);
void http_hook_query(zl_loop_t *loop, const char *app, const char *tc_url,
                     const char *stream_name, const char *action,
                     http_hook_cb func, void *udata);
