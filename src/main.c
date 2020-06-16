#include "log.h"
#include "event_loop.h"
#include "mpsc_queue.h"
//#include "rtsp_client.h"
//#include "rtmp_client.h"
//#include "sdp.h"
//#include "rtp_demux.h"
//#include "h26x.h"
#include "zk_util.h"
#include "timestamp.h"
#include "cfg_util.h"
//#include "hook/aco_hook_syscall.h"
#include "net/rtz_server.h"
#include "net/ice.h"
#include "net/dtls.h"
#include "net/http_hooks.h"
#include "net/tcp_chan_ssl.h"
#include "crash_util.h"
#include "watchdog.h"
#include "rtz_shard.h"
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

const char *ZK_HOST = NULL;
const char *RTZ_PUBLIC_IP = NULL;
const char *RTZ_PUBLIC_IPV6 = NULL;
const char *RTZ_LOCAL_IP = NULL;
int RTZ_PUBLIC_SIGNAL_PORT = 443;
int RTZ_LOCAL_SIGNAL_PORT = 443;
int RTZ_PUBLIC_HLS_PORT = 8086;
int RTZ_LOCAL_HLS_PORT = 8086;
int RTZ_PUBLIC_MEDIA_PORT = 6000;
int RTZ_LOCAL_MEDIA_PORT = 6000; /* rtmp push */
int RTMP_PUBLIC_PORT = 1935;
int RTMP_LOCAL_PORT = 1935;
int RTZ_MONITOR_PORT = 1985;
const char *CERT_PEM = NULL;
const char *CERT_KEY = NULL;
const char *ORIGIN_HOST = NULL;
static const char *CERT_PWD = NULL;
const char *HTTP_HOOKS_URL = NULL; /* http://172.16.3.101:2000/streamcloud-control-service/srs/appgw/auth */
int RTZ_SHARDS = 1;

void signal_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    struct signalfd_siginfo si;
    int n;
    n = read(fd, &si, sizeof(struct signalfd_siginfo));
    while (n == sizeof(struct signalfd_siginfo)) {
        LLOG(LL_WARN, "terminating by signal %d(%s), be patient...",
             si.ssi_signo, strsignal(si.ssi_signo));
        n = read(fd, &si, sizeof(struct signalfd_siginfo));
    }
    zl_stop(loop);
}

static void test_http_hook_handler(zl_loop_t *loop, long client_id,
                                   int result, void *udata)
{
    LLOG(LL_DEBUG, "hook client_id=%ld result=%d", client_id, result);
}
static void test_http_hooks(zl_loop_t *loop)
{
    http_hook_on_play(loop, "live", "rtmp://172.20.226.86/live", "stream", 123, test_http_hook_handler, NULL);
}

int main(int argc, char *argv[])
{
    srand48(time(NULL));
    srand(time(NULL));

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
    RTZ_SHARDS = cfg_get_int(cfg, "RTZ_SHARDS", 1);
    ZK_HOST = cfg_get_text(cfg, "ZK_HOST", NULL);
    RTZ_LOCAL_IP = cfg_get_text(cfg, "RTZ_LOCAL_IP", "127.0.0.1");
    RTZ_PUBLIC_IP = cfg_get_text(cfg, "RTZ_PUBLIC_IP", RTZ_LOCAL_IP);
    RTZ_PUBLIC_IPV6 = cfg_get_text(cfg, "RTZ_PUBLIC_IPV6", NULL);
    RTZ_LOCAL_SIGNAL_PORT = cfg_get_int(cfg, "RTZ_LOCAL_SIGNAL_PORT", 443);
    RTZ_LOCAL_HLS_PORT = cfg_get_int(cfg, "RTZ_LOCAL_HLS_PORT", 8086);
    RTZ_PUBLIC_HLS_PORT = cfg_get_int(cfg, "RTZ_PUBLIC_HLS_PORT", RTZ_LOCAL_HLS_PORT);
    RTZ_PUBLIC_SIGNAL_PORT = cfg_get_int(cfg, "RTZ_PUBLIC_SIGNAL_PORT", RTZ_LOCAL_SIGNAL_PORT);
    RTZ_LOCAL_MEDIA_PORT = cfg_get_int(cfg, "RTZ_LOCAL_MEDIA_PORT", 6000);
    RTZ_PUBLIC_MEDIA_PORT = cfg_get_int(cfg, "RTZ_PUBLIC_MEDIA_PORT", RTZ_LOCAL_MEDIA_PORT);
    RTMP_LOCAL_PORT = cfg_get_int(cfg, "RTMP_LOCAL_PORT", 1935);
    RTMP_PUBLIC_PORT = cfg_get_int(cfg, "RTMP_PUBLIC_PORT", RTMP_LOCAL_PORT);
    CERT_PEM = cfg_get_text(cfg, "CERT_PEM", "rtz.pem");
    CERT_KEY = cfg_get_text(cfg, "CERT_KEY", "rtz.key");
    ORIGIN_HOST = cfg_get_text(cfg, "ORIGIN_HOST", NULL);
    HTTP_HOOKS_URL = cfg_get_text(cfg, "HTTP_HOOKS_URL", NULL);
    RTZ_MONITOR_PORT = (RTMP_LOCAL_PORT < 10000)
        ? RTMP_LOCAL_PORT + 50
        : RTMP_LOCAL_PORT + 500;
    cfg_del(cfg);
    LLOG(LL_INFO, "#RTZ_VERSION=%s %s", RTZ_VERSION, __DATE__);
    LLOG(LL_INFO, "#WITH_WSS=%d",
#if WITH_WSS
        1
#else
        0
#endif
    );
    LLOG(LL_INFO, "#WITH_ZOOKEEPER=%d",
#if WITH_ZOOKEEPER
        1
#else
        0
#endif
    );
    LLOG(LL_INFO, "#WITH_SYSTEMD=%d",
#if WITH_SYSTEMD
        1
#else
        0
#endif
    );

    LLOG(LL_INFO, "RTZ_SHARDS=%d", RTZ_SHARDS);
    LLOG(LL_INFO, "ZK_HOST=%s", ZK_HOST);
    LLOG(LL_INFO, "RTZ_PUBLIC_IPV6=%s", RTZ_PUBLIC_IPV6 ?: "<disabled>");
    LLOG(LL_INFO, "RTZ_LOCAL_IP:SIGNAL_PORT,MEDIA_PORT,RTMP_PORT,HLS_PORT,MONITOR_PORT=%s:%d,%d,%d,%d,%d",
         RTZ_LOCAL_IP, RTZ_LOCAL_SIGNAL_PORT, RTZ_LOCAL_MEDIA_PORT, RTMP_LOCAL_PORT, RTZ_LOCAL_HLS_PORT, RTZ_MONITOR_PORT);
    LLOG(LL_INFO, "RTZ_PUBLIC_IP:SIGNAL_PORT,MEDIA_PORT,RTMP_PORT,HLS_PORT=%s:%d,%d,%d,%d",
         RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT, RTZ_PUBLIC_MEDIA_PORT, RTMP_PUBLIC_PORT, RTZ_PUBLIC_HLS_PORT);
    LLOG(LL_INFO, "CERT_PEM=%s", CERT_PEM);
    LLOG(LL_INFO, "CERT_KEY=%s", CERT_KEY);
    LLOG(LL_INFO, "ORIGIN_HOST=%s", ORIGIN_HOST);
    LLOG(LL_INFO, "HTTP_HOOKS_URL=%s", HTTP_HOOKS_URL);

    if (!ORIGIN_HOST) {
        LLOG(LL_FATAL, "ORIGIN_HOST is required in edge mode.");
        llog_cleanup();
        return - 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#if WITH_WSS
    tcp_ssl_init(CERT_PEM, CERT_KEY, CERT_PWD);
#endif
    dtls_srtp_init(CERT_PEM, CERT_KEY, CERT_PWD);

	zl_loop_t *main_loop = zl_loop_new(4096);
    zl_loop_set_ct(main_loop);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    zl_fd_ctl(main_loop, EPOLL_CTL_ADD, sfd, EPOLLIN, signal_event_handler, main_loop);

    if (ZK_HOST)
        start_zk_registry(main_loop);

    start_watchdog(main_loop);
    start_rtz_shards(main_loop);

    while (!zl_loop_stopped(main_loop)) {
        zl_poll(main_loop, 1000);
	}

    if (ZK_HOST)
        stop_zk_registry();

    stop_rtz_shards();

    long long ts = zl_timestamp();
    do {
        zl_poll(main_loop, 100);
    } while (ts + 5000 > zl_timestamp());

    stop_watchdog();

    zl_fd_ctl(main_loop, EPOLL_CTL_DEL, sfd, 0, NULL, NULL);
    close(sfd);

    zl_loop_del(main_loop);

#if WITH_WSS
    tcp_ssl_cleanup();
#endif
    dtls_srtp_cleanup();
    EVP_cleanup();
    ERR_free_strings();
    OPENSSL_cleanup();

    llog_cleanup();
	return 0;
}
