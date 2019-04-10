#include "rtz_shard.h"
#include "net/rtz_server.h"
#include "event_loop.h"
#include "macro_util.h"
#include "log.h"
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
};

extern int RTZ_SHARDS;
extern int RTZ_LOCAL_SIGNAL_PORT;
static rtz_shard_t *rtz_shards[MAX_RTZ_SHARDS] = {};
static __thread int rtz_shard_index_ct = -1;

static rtz_shard_t *shard_new(int idx);
static void rtz_shard_del(rtz_shard_t *d);
static void *shard_entry(void *arg);
static void stop_shard(zl_loop_t *loop, void *udata);
static void after_stop_shard(zl_loop_t *loop, void *udata);

void start_rtz_shards()
{
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
    LLOG(LL_INFO, "shard %d starting...", d->idx);

    rtz_shard_index_ct = d->idx;
    d->loop = zl_loop_new(4096);
    zl_loop_set_ct(d->loop);

    d->rtz_srv = rtz_server_new(d->loop);
    rtz_server_bind(d->rtz_srv, RTZ_LOCAL_SIGNAL_PORT);
    rtz_server_start(d->rtz_srv);

    while (!zl_loop_stopped(d->loop)) {
        zl_poll(d->loop, 100);
    }

    LLOG(LL_INFO, "shard %d stopping...", d->idx);
    rtz_server_stop(d->rtz_srv);

    long long ts = zl_timestamp();
    do {
        zl_poll(d->loop, 100);
    } while (ts + 5000 > zl_timestamp());

    rtz_server_del(d->rtz_srv);
    d->rtz_srv = NULL;
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
