#pragma once
typedef struct zl_loop_t zl_loop_t;
typedef struct rtz_server_t rtz_server_t;

enum {
    MAX_RTZ_SHARDS = 16,
};

void start_rtz_shards(zl_loop_t *control_loop);
void stop_rtz_shards();
int rtz_shard_get_index_ct();
rtz_server_t *rtz_shard_get_server_ct();
zl_loop_t *rtz_shard_get_loop(int idx);
zl_loop_t *rtz_shard_get_control_loop();
int rtz_get_total_load();
void rtz_kick_stream(const char *tc_url, const char *stream);
