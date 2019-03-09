#pragma once
#include <sys/epoll.h>

#define ZL_USEC_PER_SEC 1000000
#define ZL_MSEC_PER_SEC 1000

typedef struct zl_loop_t zl_loop_t;
typedef void (*zl_fd_event_cb)(zl_loop_t *loop, int fd, uint32_t events, void *udata);
typedef void (*zl_timerfd_event_cb)(zl_loop_t *loop, int fd, uint64_t expires, void *udata);
typedef void (*zl_timer_cb)(zl_loop_t *loop, int id, void *udata);
typedef void (*zl_defer_cb)(zl_loop_t *loop, int64_t status, void *udata);
typedef void (*zl_job_cb)(zl_loop_t *loop, void *udata);

zl_loop_t *zl_loop_new(int setsize);
void zl_loop_del(zl_loop_t *loop);
int zl_loop_stopped(zl_loop_t *loop);
void zl_stop(zl_loop_t *loop);
int zl_poll(zl_loop_t *loop, int timeout);
int zl_fd_ctl(zl_loop_t *loop, int op, int fd, uint32_t events, zl_fd_event_cb func, void* udata);

int zl_timer_start(zl_loop_t *loop, long delay, long repeat, zl_timer_cb func, void *udata);
void zl_timer_stop(zl_loop_t *loop, int id);
void zl_timer_again(zl_loop_t *loop, int id, long delay, long repeat);

/** micro-seconds */
long long zl_hrtimestamp();
/** milliseconds */
long long zl_timestamp ();
/** micro-seconds */
long long zl_hrtime();
/** milliseconds */
long long zl_time();

void zl_defer(zl_loop_t *loop, zl_defer_cb cb, int64_t status, void *udata);

// inter-thread invoke
zl_loop_t *zl_loop_get_ct();
void zl_loop_set_ct(zl_loop_t *loop);
void zl_invoke(zl_loop_t *loop, zl_job_cb cb, void *udata);
void zl_invoke2(zl_loop_t *loop, zl_job_cb cb, zl_job_cb after_cb, void *udata);
