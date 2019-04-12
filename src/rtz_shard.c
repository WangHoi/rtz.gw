#include "rtz_shard.h"
#include "net/rtz_server.h"
#include "net/nbuf.h"
#include "event_loop.h"
#include "macro_util.h"
#include "log.h"
#include "sched_util.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct rtz_shard_t rtz_shard_t;
struct rtz_shard_t {
    pthread_t tid;

    int idx;
    zl_loop_t *loop;
    rtz_server_t *rtz_srv;
    int load;
};

extern int RTZ_SHARDS;
extern int RTZ_LOCAL_SIGNAL_PORT;
static rtz_shard_t *rtz_shards[MAX_RTZ_SHARDS] = {};
static __thread int rtz_shard_index_ct = -1;
static zl_loop_t *rtz_control_loop = NULL;
static int rtz_total_load = 0;

static rtz_shard_t *shard_new(int idx);
static void rtz_shard_del(rtz_shard_t *d);
static void *shard_entry(void *arg);
static void stop_shard(zl_loop_t *loop, void *udata);
static void after_stop_shard(zl_loop_t *loop, void *udata);
static void get_shard_load(zl_loop_t *loop, void *udata);
static void update_total_load(zl_loop_t *loop, void *udata);

void start_rtz_shards(zl_loop_t *control_loop)
{
    rtz_control_loop = control_loop;
    int i;
    for (i = 0; i < RTZ_SHARDS; ++i) {
        rtz_shards[i] = shard_new(i);
    }
}

void stop_rtz_shards()
{
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
    if (idx >= 0 && idx < ARRAY_SIZE(rtz_shards)
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
    zl_invoke(rtz_shards[0]->loop, get_shard_load, 0);
    return rtz_total_load;
}

rtz_shard_t *shard_new(int idx)
{
    rtz_shard_t *d = malloc(sizeof(rtz_shard_t));
    memset(d, 0, sizeof(rtz_shard_t));
    d->idx = idx;

    WRITE_FENCE;

    int ret;
    do {
        ret = pthread_create(&d->tid, NULL, shard_entry, d);
    } while (ret);
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

    while (!zl_loop_stopped(d->loop)) {
        zl_poll(d->loop, 1000);
    }

    LLOG(LL_INFO, "shard %d stopping...", d->idx);
    rtz_server_stop(d->rtz_srv);

    long long ts = zl_timestamp();
    do {
        zl_poll(d->loop, 100);
    } while (ts + 5000 > zl_timestamp());

    rtz_server_del(d->rtz_srv);
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
    zl_stop(loop);
}

void after_stop_shard(zl_loop_t *loop, void *udata)
{
    rtz_shard_t *d = udata;
    int ret;
    LLOG(LL_INFO, "joining shard %d thread...", d->idx);
    ret = pthread_tryjoin_np(d->tid, NULL);
    while (ret) {
        sleep(1);
        ret = pthread_tryjoin_np(d->tid, NULL);
    }
    free(d);
}

void get_shard_load(zl_loop_t *loop, void *udata)
{
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

void update_total_load(zl_loop_t *loop, void *udata)
{
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
