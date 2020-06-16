#include "event_loop.h"
#include "list.h"
#include "mpsc_queue.h"
#include "macro_util.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include <assert.h>
#include <limits.h>
#include <time.h>

enum {
    ZL_JOB_QUEUE_DEFAULT_SIZE_ORDER = 20,
};

struct fd_event {
    uint32_t events;
    zl_fd_event_cb func;
    void *udata;
};

struct job_event {
    zl_loop_t *src_loop;
    zl_loop_t *dst_loop;
    zl_job_cb cb;
    zl_job_cb after_cb;
    void *udata;
    struct list_head link;
};

struct defer_event {
    zl_defer_cb func;
    int64_t status;
    void *udata;
    struct list_head link;
};

struct timer_event {
    int id;
    zl_timer_cb func;
    void *udata;
    long long deadline;
    long repeat;
    struct list_head link;
};

struct zl_loop_t {
    struct epoll_event *eevents;
    struct fd_event *fds;
    int epoll_fd;
    int evt_fd;
    int stop;
    int eevents_cnt;
    int setsize;
    void* udata;
    struct list_head defer_list;
    struct mpsc_queue *job_queue;
    struct list_head stage_job_list;
    struct list_head timer_list;
};

static __thread zl_loop_t *ct_loop = NULL;

static int run_defer_funcs(zl_loop_t *loop);
static int run_jobs(zl_loop_t *loop);
static int run_timers(zl_loop_t *loop, int *first_timeout);
static int new_timer_id(zl_loop_t *loop);
static struct timer_event *find_timer(zl_loop_t *loop, int id);
static void loop_evtfd_event_cb(zl_loop_t *loop, int fd, uint32_t events, void *udata);

zl_loop_t *zl_loop_new(int setsize)
{
    zl_loop_t *loop;

    if (setsize <= 0)
        return NULL;
    loop = malloc(sizeof(zl_loop_t));
    if (loop == NULL)
        return NULL;
    loop->eevents = calloc((size_t)setsize, sizeof(struct epoll_event));
    if (loop->eevents == NULL)
        goto err_ep_evts;
    loop->fds = calloc((size_t)setsize, sizeof(struct fd_event));
    if (loop->fds == NULL)
        goto err_fd_evts;
    loop->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (loop->epoll_fd == -1) {
        printf("epoll_create1 error: %s\n", strerror(errno));
        goto err_epfd;
    }
    loop->stop = 0;
    loop->eevents_cnt = 0;
    loop->setsize = setsize;
    loop->udata = NULL;
    INIT_LIST_HEAD(&loop->defer_list);
    loop->job_queue = mpsc_queue_new(ZL_JOB_QUEUE_DEFAULT_SIZE_ORDER);
    INIT_LIST_HEAD(&loop->stage_job_list);
    INIT_LIST_HEAD(&loop->timer_list);

    loop->evt_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    zl_fd_ctl(loop, EPOLL_CTL_ADD, loop->evt_fd, EPOLLIN, loop_evtfd_event_cb, loop);
    return loop;
err_epfd:
    free(loop->fds);
err_fd_evts:
    free(loop->eevents);
err_ep_evts:
    free(loop);
    return NULL;
}

void zl_loop_del(zl_loop_t *loop)
{
    if (!loop)
        return;

    zl_fd_ctl(loop, EPOLL_CTL_DEL, loop->evt_fd, 0, NULL, NULL);
    close(loop->evt_fd);
    mpsc_queue_del(loop->job_queue);
    close(loop->epoll_fd);
    free(loop->eevents);
    free(loop->fds);
    free(loop);
}

int zl_loop_stopped(zl_loop_t *loop)
{
    return loop->stop;
}

void zl_stop(zl_loop_t *loop)
{
    loop->stop = 1;
}

int zl_poll(zl_loop_t *loop, int timeout)
{
    int ret, i, ne = 0;
    long long ts1 = zl_time();
    ne += run_timers(loop, &timeout);
    if (!list_empty(&loop->stage_job_list))
        timeout = 0;

    long long ts2 = zl_time();
    ret = epoll_wait(loop->epoll_fd, loop->eevents, loop->setsize, timeout);
    long long ts3 = zl_time();
    if (ret == -1)
        loop->eevents_cnt = 0;
    else
        loop->eevents_cnt = ret;
    for (i = 0; i < loop->eevents_cnt; ++i) {
        struct epoll_event *ee = &loop->eevents[i];
        struct fd_event *fe = &loop->fds[ee->data.fd];
        if (fe->func) {
            fe->func(loop, ee->data.fd, ee->events, fe->udata);
            ++ne;
        }
    }
    ne += run_defer_funcs(loop);
    ne += run_jobs(loop);
    long long ts4 = zl_time();
    long long dt = (ts4 - ts3) + (ts2 - ts1);
    if (dt > 40)
        LLOG(LL_WARN, "event loop cost %lld ms", dt);
    return ne;
}

int zl_fd_ctl(zl_loop_t *loop, int op, int fd, uint32_t events, zl_fd_event_cb func, void *udata)
{
    if (fd < 0) {
        LLOG(LL_FATAL, "fd %d invalid", fd);
        return -1;
    }
    if (fd >= loop->setsize) {
        LLOG(LL_FATAL, "fd %d larger than pollset size %d", fd, loop->setsize);
        return -1;
    }
    struct fd_event *fe = &loop->fds[fd];
    fe->events = events;
    fe->func = func;
    fe->udata = udata;
    struct epoll_event ee;
    ee.events = events;
    memset(&ee.data, 0, sizeof(ee.data));
    ee.data.fd = fd;
    return epoll_ctl(loop->epoll_fd, op, fd, &ee);
}

long long zl_hrtimestamp()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

long long zl_timestamp()
{
    struct timespec ts;
    clock_gettime (CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

long long zl_hrtime()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

long long zl_time()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void zl_defer(zl_loop_t *loop, zl_defer_cb func, int64_t status, void *udata)
{
    assert(func);
    struct defer_event *defer = malloc(sizeof(struct defer_event));
    assert(defer);
    defer->func = func;
    defer->status = status;
    defer->udata = udata;
    list_add_tail(&defer->link, &loop->defer_list);
    const int64_t d = 1;
    UNUSED(write(loop->evt_fd, &d, 8));
}

int run_defer_funcs(zl_loop_t *loop)
{
    struct defer_event *d, *tmp;
    int n = 0;
    list_for_each_entry_safe(d, tmp, &loop->defer_list, link) {
        d->func(loop, d->status, d->udata);
        free(d);
        ++n;
    }
    INIT_LIST_HEAD(&loop->defer_list);
    return n;
}

int run_jobs(zl_loop_t *loop)
{
    struct job_event *je, *tmp;
    int n = 0;
    struct mpsc_msg *msg;

    while ((msg = mpsc_peek(loop->job_queue)) != NULL) {
        je = (struct job_event*)&msg->u64[0];
        je->cb(loop, je->udata);
        if (je->after_cb)
            zl_invoke(je->src_loop, je->after_cb, je->udata);
        mpsc_consume(loop->job_queue, msg);
    }

    list_for_each_entry_safe(je, tmp, &loop->stage_job_list, link) {
        msg = mpsc_reserve(je->dst_loop->job_queue);
        if (!msg)
            break;
        memcpy(&msg->u64[0], je, sizeof(struct job_event));
        mpsc_commit(msg, 1);
        list_del(&je->link);
        free(je);
    }

    return n;
}

zl_loop_t *zl_loop_get_ct()
{
    return ct_loop;
}

void zl_loop_set_ct(zl_loop_t *loop)
{
    ct_loop = loop;
}

void zl_invoke(zl_loop_t *loop, zl_job_cb cb, void *udata)
{
    zl_invoke2(loop, cb, NULL, udata);
}

void zl_invoke2(zl_loop_t *loop, zl_job_cb cb, zl_job_cb after_cb, void *udata)
{
    assert(cb);
    assert(ct_loop);
    assert(ct_loop != loop);
    struct job_event *je = malloc(sizeof(struct job_event));
    je->src_loop = ct_loop;
    je->dst_loop = loop;
    je->cb = cb;
    je->after_cb = after_cb;
    je->udata = udata;
    list_add_tail(&je->link, &ct_loop->stage_job_list);
    const int64_t d = 1;
    UNUSED(write(loop->evt_fd, &d, sizeof(d)));
}

int zl_timer_start(zl_loop_t *loop, long delay, long repeat, zl_timer_cb func, void *udata)
{
    int id = new_timer_id(loop);
    if (id == -1)
        return -1;
    struct timer_event *t = malloc(sizeof(struct timer_event));
    t->id = id;
    t->deadline = zl_timestamp() + delay;
    t->repeat = repeat;
    t->func = func;
    t->udata = udata;
    list_add(&t->link, &loop->timer_list);
    return id;
}

void zl_timer_again(zl_loop_t *loop, int id, long delay, long repeat)
{
    struct timer_event *t = find_timer(loop, id);
    if (t) {
        t->deadline = zl_timestamp() + delay;
        t->repeat = repeat;
    }
}

void zl_timer_stop(zl_loop_t *loop, int id)
{
    struct timer_event *t = find_timer(loop, id);
    if (t) {
        list_del(&t->link);
        free(t);
    }
}

static int new_timer_id(zl_loop_t *loop)
{
    if (list_empty(&loop->timer_list))
        return 0;
    struct timer_event *t;
    t = list_entry(loop->timer_list.prev, struct timer_event, link);
    int new_id = t->id, i;
    for (i = 0; i < INT_MAX; ++i) {
        if (new_id == INT_MAX)
            new_id = 0;
        else
            ++new_id;
        if (!find_timer(loop, new_id))
            return new_id;
    }
    return -1;
}

struct timer_event *find_timer(zl_loop_t *loop, int id)
{
    struct timer_event *t;
    list_for_each_entry(t, &loop->timer_list, link) {
        if (t->id == id)
            return t;
    }
    return NULL;
}

int run_timers(zl_loop_t *loop, int *first_timeout)
{
    int n = 0;
    long long now = zl_timestamp();
    struct timer_event *t, *tmp;
    list_for_each_entry_safe(t, tmp, &loop->timer_list, link) {
        if (t->deadline && now >= t->deadline) {
            if (t->repeat > 0)
                t->deadline += t->repeat;
            else
                t->deadline = 0;
            t->func(loop, t->id, t->udata);
            ++n;
        }
    }
    list_for_each_entry(t, &loop->timer_list, link) {
        if (!t->deadline)
            continue;

        if (now >= t->deadline)
            *first_timeout = 0;
        else
            *first_timeout = MIN(*first_timeout, t->deadline - now);
    }
    return n;
}

void loop_evtfd_event_cb(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    int64_t d = 1;
    UNUSED(read(fd, &d, 8));
}
