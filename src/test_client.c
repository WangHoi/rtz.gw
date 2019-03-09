#include "log.h"
#include "event_loop.h"
#include <uv.h>
#include <stdlib.h>
#include <string.h>

const int scratch_size = 256 * 1024;
char *scratch_buf = NULL;
const char *ip = NULL;
int count = 0;

typedef struct client_t {
    //uv_timer_t *timer;
    uv_tcp_t *client;
} client_t;
/*
static void on_timeout(uv_timer_t *timer)
{
    client_t *p = timer->data;
    uv_buf_t buf = uv_buf_init(scratch_buf, scratch_size);
    long long ts = zl_timestamp();
    int n = uv_try_write((uv_stream_t*)p->client, &buf, 1);
    ts = zl_timestamp() - ts;
    LLOG(LL_TRACE, "write %d cost %lld ms", n, ts);
}
*/
static void on_alloc(uv_handle_t *h, size_t suggested_size, uv_buf_t *buf)
{
    buf->base = malloc(suggested_size);
    buf->len = suggested_size;
}

static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    client_t *p = stream->data;
    if (nread < 0) {
        LLOG(LL_ERROR, "peer error %s", uv_strerror(nread));
    }
    free(buf->base);
}

static void on_connect(uv_connect_t* req, int status)
{
    if (status == 0) {
        client_t *p = req->handle->data;
        uv_read_start((uv_stream_t*)p->client, on_alloc, on_read);
    }
    free(req);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
        return -1;
    ip = argv[1];
    count = atoi(argv[2]);

    llog_init(1, "test_client.log");

    scratch_buf = malloc(scratch_size);

    uv_loop_t *loop = uv_default_loop();

    int i;
    struct sockaddr_in addr = {};
    uv_ip4_addr(ip, 12345, &addr);
    for (i = 0; i < count; ++i) {
        client_t *c = malloc(sizeof(client_t));
        c->client = malloc(sizeof(uv_tcp_t));
        c->client->data = c;
        uv_tcp_init(loop, c->client);
        uv_connect_t *req = malloc(sizeof(uv_connect_t));
        uv_tcp_connect(req, c->client, (struct sockaddr*)&addr, on_connect);
    }

    uv_run(loop, UV_RUN_DEFAULT);

    free(scratch_buf);

    llog_cleanup();
    return 0;
}
