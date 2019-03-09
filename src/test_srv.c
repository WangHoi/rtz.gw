#include "log.h"
#include "event_loop.h"
#include "list.h"
#include <uv.h>
#include <stdlib.h>
#include <string.h>

const int scratch_size = 2 * 1024 * 1024 / 8 / 25;
char *scratch_buf = NULL;
LIST_HEAD(peer_list);
uv_timer_t *timer;

typedef struct peer_t {
    uv_tcp_t *client;
    struct list_head link;
} peer_t;


static void on_write(uv_write_t *req, int n)
{
    free(req);
}

static void on_timeout(uv_timer_t *timer)
{
    peer_t *p;
    list_for_each_entry(p, &peer_list, link) {
        uv_buf_t buf = uv_buf_init(scratch_buf, scratch_size);
        uv_write_t *req = malloc(sizeof(uv_write_t));
        uv_write(req, (uv_stream_t*)p->client, &buf, 1, on_write);
    }
}

static void on_alloc(uv_handle_t *h, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    peer_t *p = stream->data;
    if (nread < 0) {
        LLOG(LL_ERROR, "peer error %s", uv_strerror(nread));
    }
    free(buf->base);
}

static void on_connection(uv_stream_t* server, int status)
{
    peer_t *p = malloc(sizeof(peer_t));
    p->client = malloc(sizeof(uv_tcp_t));
    p->client->data = p;
    list_add(&p->link, &peer_list);
    uv_tcp_init(server->loop, p->client);
    uv_accept(server, p->client);
    uv_read_start((uv_stream_t*)p->client, on_alloc, on_read);
}

long long last_ts = 0;
static void loop_info(uv_idle_t *idle)
{
    long long ts = zl_timestamp();
    if (last_ts) {
        if (ts - last_ts > 2)
            LLOG(LL_TRACE, "loop cost %lld", ts - last_ts);
    }
    last_ts = ts;
}

int main(int argc, char *argv[])
{
    llog_init(1, "test_srv.log");

    uv_idle_t idler;
    uv_idle_init(uv_default_loop(), &idler);
    uv_idle_start(&idler, loop_info);

    scratch_buf = malloc(scratch_size);

    uv_loop_t *loop = uv_default_loop();
    uv_tcp_t *tcp = malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, tcp);
    struct sockaddr_in addr = {};
    uv_ip4_addr("0.0.0.0", 12345, &addr);
    uv_tcp_bind(tcp, (struct sockaddr*)&addr, 0);
    uv_listen((uv_stream_t*)tcp, 4, on_connection);

    timer = malloc(sizeof(uv_timer_t));
    uv_timer_init(loop, timer);
    uv_timer_start(timer, on_timeout, 40, 40);

    uv_run(loop, UV_RUN_DEFAULT);

    free(scratch_buf);

    llog_cleanup();
    return 0;
}
