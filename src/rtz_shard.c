#include "rtz_shard.h"
#include "net/rtz_server.h"
#include "net/monitor_server.h"
#include "net/hls_server.h"
#include "net/nbuf.h"
#include "event_loop.h"
#include "macro_util.h"
#include "sbuf.h"
#include "log.h"
#include "sched_util.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct rtz_shard_t rtz_shard_t;
struct rtz_shard_t {
    pthread_t tid;
    pthread_barrier_t start_barrier;

    int idx;
    zl_loop_t *loop;
    rtz_server_t *rtz_srv;
    hls_server_t *hls_srv;
    int load;
};

struct rtz_kick_udata {
    sbuf_t *tc_url;
    sbuf_t *stream;
};

extern int RTZ_SHARDS;
extern int RTZ_LOCAL_SIGNAL_PORT;
extern int RTZ_LOCAL_HLS_PORT;
extern int RTZ_MONITOR_PORT;
static rtz_shard_t *rtz_shards[MAX_RTZ_SHARDS] = {};
static __thread int rtz_shard_index_ct = -1;
static zl_loop_t *rtz_control_loop = NULL;
static int rtz_total_load = 0;
static volatile int shards_stopping = 0;
static monitor_server_t *mon_srv = NULL;

static rtz_shard_t *shard_new(int idx);
static void rtz_shard_del(rtz_shard_t *d);
static void *shard_entry(void *arg);
static void stop_shard(zl_loop_t *loop, void *udata);
static void after_stop_shard(zl_loop_t *loop, void *udata);
static void get_shard_load(zl_loop_t *loop, void *udata);
static void update_total_load(zl_loop_t *loop, void *udata);
static void kick_stream(zl_loop_t *loop, void *udata);

void start_rtz_shards(zl_loop_t *control_loop)
{
    rtz_control_loop = control_loop;
    int i;
    for (i = 0; i < RTZ_SHARDS; ++i) {
        rtz_shards[i] = shard_new(i);
    }
    mon_srv = monitor_server_new(control_loop);
    monitor_server_bind(mon_srv, (unsigned short)RTZ_MONITOR_PORT);
    monitor_server_start(mon_srv);
}

void stop_rtz_shards()
{
    monitor_server_stop(mon_srv);
    monitor_server_del(mon_srv);
    int i;
    for (i = 0; i < RTZ_SHARDS; ++i) {
        rtz_shard_del(rtz_shards[i]);
    }
    memset(rtz_shards, 0, sizeof(rtz_shards));
}

int rtz_shard_get_index_ct()
{
    return rtz_shard_index_ct;
}

rtz_server_t *rtz_shard_get_server_ct()
{
    if (rtz_shard_index_ct == -1 || !rtz_shards[rtz_shard_index_ct])
        return NULL;
    return rtz_shards[rtz_shard_index_ct]->rtz_srv;
}

zl_loop_t *rtz_shard_get_loop(int idx)
{
    if (idx >= 0 && idx < (int)ARRAY_SIZE(rtz_shards)
        && rtz_shards[idx])
        return rtz_shards[idx]->loop;
    return NULL;
}

zl_loop_t *rtz_shard_get_control_loop()
{
    return rtz_control_loop;
}

int rtz_get_total_load()
{
    if (!shards_stopping)
        zl_invoke(rtz_shards[0]->loop, get_shard_load, 0);
    return rtz_total_load;
}

void rtz_kick_stream(const char *tc_url, const char *stream)
{
    if (!shards_stopping) {
        struct rtz_kick_udata *ud = malloc(sizeof(struct rtz_kick_udata));
        memset(ud, 0, sizeof(struct rtz_kick_udata));
        ud->tc_url = sbuf_strdup(tc_url);
        ud->stream = sbuf_strdup(stream);
        zl_invoke(rtz_shards[0]->loop, kick_stream, ud);
    }
}

rtz_shard_t *shard_new(int idx)
{
    rtz_shard_t *d = malloc(sizeof(rtz_shard_t));
    memset(d, 0, sizeof(rtz_shard_t));
    d->idx = idx;
    pthread_barrier_init(&d->start_barrier, NULL, 2);

    FULL_FENCE;

    int ret;
    do {
        ret = pthread_create(&d->tid, NULL, shard_entry, d);
    } while (ret);
    pthread_barrier_wait(&d->start_barrier);
    return d;
}

void rtz_shard_del(rtz_shard_t *d)
{
    if (!d)
        return;
    zl_invoke2(d->loop, stop_shard, after_stop_shard, d);
}

void *shard_entry(void *arg)
{
    rtz_shard_t *d = arg;

    const int cpu_count = get_cpu_count();
    if (cpu_count > 1) {
        set_cpu_scheduler_fifo_ct();
        int cpu_core = (RTZ_SHARDS < cpu_count)
            ? (1 + d->idx) % (cpu_count - 1)
            : d->idx % cpu_count;
        set_cpu_affinity_ct(cpu_core);
        LLOG(LL_INFO, "starting shard %d on core %d...", d->idx, cpu_core);
    }

    rtz_shard_index_ct = d->idx;
    d->loop = zl_loop_new(4096);
    zl_loop_set_ct(d->loop);

    nbuf_init_free_list_ct();

    d->rtz_srv = rtz_server_new(d->loop);
    rtz_server_bind(d->rtz_srv, RTZ_LOCAL_SIGNAL_PORT);
    rtz_server_start(d->rtz_srv);

    d->hls_srv = hls_server_new(d->loop);
    hls_server_bind(d->hls_srv, RTZ_LOCAL_HLS_PORT);
    hls_server_start(d->hls_srv);

    pthread_barrier_wait(&d->start_barrier);

    while (!zl_loop_stopped(d->loop)) {
        zl_poll(d->loop, 1000);
    }

    LLOG(LL_INFO, "shard %d stopping...", d->idx);
    hls_server_stop(d->hls_srv);
    rtz_server_stop(d->rtz_srv);

    long long ts = zl_timestamp();
    do {
        zl_poll(d->loop, 100);
    } while (ts + 1000 > zl_timestamp());

    rtz_server_del(d->rtz_srv);
    hls_server_del(d->hls_srv);
    d->rtz_srv = NULL;

    nbuf_cleanup_free_list_ct();

    zl_loop_set_ct(NULL);
    zl_loop_del(d->loop);
    d->loop = NULL;
    rtz_shard_index_ct = -1;

    pthread_exit(NULL);
    return NULL;
}

void stop_shard(zl_loop_t *loop, void *udata)
{
    UNUSED(udata);

    zl_stop(loop);
}

void after_stop_shard(zl_loop_t *loop, void *udata)
{
    UNUSED(loop);

    rtz_shard_t *d = udata;
    shards_stopping = 1;
    LLOG(LL_INFO, "joining shard %d thread...", d->idx);
    pthread_join(d->tid, NULL);
    pthread_barrier_destroy(&d->start_barrier);
    free(d);
}

void get_shard_load(zl_loop_t *loop, void *udata)
{
    UNUSED(loop);

    rtz_shard_t *cur_shard = rtz_shards[rtz_shard_index_ct];
    cur_shard->load = rtz_get_load(cur_shard->rtz_srv);

    intptr_t total_load = (intptr_t)udata;
    total_load += cur_shard->load;

    int next_idx = rtz_shard_index_ct + 1;
    if (next_idx < RTZ_SHARDS) {
        zl_invoke(rtz_shards[next_idx]->loop, get_shard_load, (void*)total_load);
    } else {
        zl_invoke(rtz_control_loop, update_total_load, (void*)total_load);
    }
}

void kick_stream(zl_loop_t *loop, void *udata)
{
    UNUSED(loop);

    struct rtz_kick_udata *kick_udata = udata;
    rtz_shard_t *cur_shard = rtz_shards[rtz_shard_index_ct];
    rtz_server_kick_stream(cur_shard->rtz_srv, kick_udata->tc_url->data, kick_udata->stream->data);

    int next_idx = rtz_shard_index_ct + 1;
    if (next_idx < RTZ_SHARDS) {
        zl_invoke(rtz_shards[next_idx]->loop, kick_stream, kick_udata);
    } else {
        sbuf_del(kick_udata->tc_url);
        sbuf_del(kick_udata->stream);
        free(kick_udata);
    }
}

void update_total_load(zl_loop_t *loop, void *udata)
{
    UNUSED(loop);

    rtz_total_load = (intptr_t)udata;

    char text[1024];
    char *p = text;
    const char *pend = text + sizeof(text);
    p += snprintf(p, pend - p, "%4d", rtz_shards[0]->load);
    int i;
    for (i = 1; i < RTZ_SHARDS; ++i) {
        p += snprintf(p, pend - p, ",%4d", rtz_shards[i]->load);
    }
    if (RTZ_SHARDS > 1)
        p += snprintf(p, pend - p, " total=%d", rtz_total_load);
    LLOG(LL_TRACE, "shard_loads=%s", text);
}
