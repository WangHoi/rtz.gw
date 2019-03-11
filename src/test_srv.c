#include "log.h"
#include "event_loop.h"
#include "list.h"
#include "net/tcp_chan.h"
#include <stdlib.h>
#include <string.h>

const int scratch_size = 65536;
char *scratch_buf = NULL;
int timer;
LIST_HEAD(peer_list);

typedef struct peer_t {
    tcp_chan_t* client;
    struct list_head link;
} peer_t;


static void on_timeout(zl_loop_t *loop, int id, void *udata)
{
    peer_t *p;
    list_for_each_entry(p, &peer_list, link) {
        tcp_chan_write(p->client, scratch_buf, scratch_size);
    }
}

static void on_connection(tcp_srv_t *srv, tcp_chan_t *chan, void *udata)
{
    peer_t *p = malloc(sizeof(peer_t));
    p->client = chan;
    list_add(&p->link, &peer_list);
}

int main(int argc, char *argv[])
{
    llog_init(1, "test_srv.log");

    scratch_buf = malloc(scratch_size);

    zl_loop_t *loop = zl_loop_new(1024);
    tcp_srv_t *srv = tcp_srv_new(loop);
    tcp_srv_bind(srv, NULL, 12345);
    tcp_srv_set_cb(srv, on_connection, NULL);
    tcp_srv_listen(srv);

    timer = zl_timer_start(loop, 40, 40, on_timeout, NULL);

    while (1) {
        zl_poll(loop, 100);
    }

    free(scratch_buf);
    llog_cleanup();
    return 0;
}
