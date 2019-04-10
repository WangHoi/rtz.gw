#pragma once
typedef struct zl_loop_t zl_loop_t;
typedef struct rtz_server_t rtz_server_t;

enum {
    MAX_RTZ_SHARDS = 16,
};

void start_rtz_shards();
void stop_rtz_shards();
int rtz_shard_get_index_ct();
rtz_server_t *rtz_shard_get_server_ct();
zl_loop_t *rtz_shard_get_loop(int idx);
