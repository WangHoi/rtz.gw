#include "log.h"
#include "event_loop.h"
#include "mpsc_queue.h"
#include "rtz_client.h"
#include "crash_util.h"
#include "net/monitor_server.h"
#include "timestamp.h"
#include "cfg_util.h"
#include "net/ice.h"
#include "net/dtls.h"
#include "net/rtmp_server.h"
#include "net/http_hooks.h"
#include "net/tcp_chan_ssl.h"
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <math.h>

int RTZ_BENCH_CLIENTS = 1;
const char *RTZ_BENCH_URL = NULL;
rtz_client_t *test_clients[1024] = {};
int starting_index = 0;

static void start_tests();
static void stop_tests();
static void test_rtz_client(zl_loop_t *loop);
static void signal_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    struct signalfd_siginfo si;
    int n;
    n = read(fd, &si, sizeof(struct signalfd_siginfo));
    while (n == sizeof(struct signalfd_siginfo)) {
        LLOG(LL_WARN, "terminating by signal %d(%s).",
             si.ssi_signo, strsignal(si.ssi_signo));
        n = read(fd, &si, sizeof(struct signalfd_siginfo));
    }
    zl_stop(loop);
}

int main(int argc, char *argv[])
{
    srand48(0);
    srand(0);

    sigset_t mask;
    int sfd;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGTTIN);
    sigaddset(&mask, SIGTTOU);
    sigaddset(&mask, SIGTSTP);
    sigaddset(&mask, SIGURG);
    sigaddset(&mask, SIGIO);
    sigaddset(&mask, SIGHUP);
    sigprocmask(SIG_BLOCK, &mask, NULL);

    install_crash_handler();

    llog_init();
    LLOG(LL_INFO, "starting...");

    cfg_t *cfg = cfg_new();
    RTZ_BENCH_CLIENTS = cfg_get_int(cfg, "RTZ_BENCH_CLIENTS", 1);
    RTZ_BENCH_URL = cfg_get_text(cfg, "RTZ_BENCH_URL", NULL);
    LLOG(LL_INFO, "RTZ_BENCH_CLIENTS=%d", RTZ_BENCH_CLIENTS);
    LLOG(LL_INFO, "RTZ_BENCH_URL=%s", RTZ_BENCH_URL);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    dtls_srtp_init(NULL, NULL, NULL);
#if RTZ_SERVER_SSL
    tcp_ssl_init(CERT_PEM, CERT_KEY, CERT_PWD);
#endif

    zl_loop_t *main_loop = zl_loop_new(4096);
    zl_loop_set_ct(main_loop);

    start_tests();

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    zl_fd_ctl(main_loop, EPOLL_CTL_ADD, sfd, EPOLLIN, signal_event_handler, main_loop);

    while (!zl_loop_stopped(main_loop)) {
        zl_poll(main_loop, 100);
    }

    stop_tests();

    long long ts = zl_timestamp();
    do {
        zl_poll(main_loop, 100);
    } while (ts + 1000 > zl_timestamp());


    zl_fd_ctl(main_loop, EPOLL_CTL_DEL, sfd, 0, NULL, NULL);
    close(sfd);

    zl_loop_del(main_loop);

#if RTZ_SERVER_SSL
    tcp_ssl_cleanup();
#endif
    dtls_srtp_cleanup();
    EVP_cleanup();
    ERR_free_strings();

    cfg_del(cfg);
    llog_cleanup();
    return 0;
}

void rtz_hangup(void *rtz_handle)
{
    LLOG(LL_TRACE, "%p rtz_hangup", rtz_handle);
}

void rtz_webrtcup(void *rtz_handle)
{
    LLOG(LL_TRACE, "%p rtz_webrtcup", rtz_handle);
}

static int parse_url(const char *url, char *ip, unsigned *port)
{
    const char *p = strchr(url + 7, ':');
    if (!p)
        return -1;
    if (p - (url + 7) > 32)
        return -2;
    memcpy(ip, url + 7, p - (url + 7));
    ip[p - (url + 7)] = 0;
    *port = atoi(p + 1);
    //LLOG(LL_TRACE, "ip='%s' port=%u", ip, *port);
    return 0;
}

static void start_test_timeout_handler(zl_loop_t *loop, int timer, void *udata)
{
    if (starting_index >= RTZ_BENCH_CLIENTS) {
        zl_timer_stop(loop, timer);
        return;
    }
    char ip[32];
    unsigned port;
    int ret = parse_url(RTZ_BENCH_URL, ip, &port);
    int i = starting_index++;
    test_clients[i] = rtz_client_new(loop);
    rtz_client_open(test_clients[i], ip, (int)port);
    rtz_client_play(test_clients[i], RTZ_BENCH_URL);
    zl_timer_again(loop, timer, rand() % 100, 0);
}

void start_tests()
{
    zl_loop_t *loop = zl_loop_get_ct();
    zl_timer_start(loop, 0, 0, start_test_timeout_handler, NULL);
}

void stop_tests()
{
    int i;
    for (i = 0; i < RTZ_BENCH_CLIENTS; ++i) {
        rtz_client_del(test_clients[i]);
        test_clients[i] = NULL;
    }
}

/* dummy defines */
int rtz_shard_get_index_ct()
{
    return -1;
}

zl_loop_t *rtz_shard_get_loop(int idx)
{
    return NULL;
}

void *rtz_get_ice_server(rtz_server_t *srv)
{
    return NULL;
}

rtz_server_t* rtz_shard_get_server_ct()
{
    return NULL;
}
