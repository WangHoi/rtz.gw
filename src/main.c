#include "log.h"
#include "event_loop.h"
#include "mpsc_queue.h"
//#include "rtsp_client.h"
//#include "rtmp_client.h"
//#include "sdp.h"
//#include "rtp_demux.h"
//#include "h26x.h"
#include "zk_util.h"
#include "net/monitor_server.h"
#include "timestamp.h"
#include "cfg_util.h"
//#include "hook/aco_hook_syscall.h"
#include "net/rtz_server.h"
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

const char *ZK_HOST = NULL;
const char *RTZ_PUBLIC_IP = NULL;
const char *RTZ_LOCAL_IP = NULL;
int RTZ_PUBLIC_SIGNAL_PORT = 443;
int RTZ_LOCAL_SIGNAL_PORT = 443;
int RTZ_PUBLIC_MEDIA_PORT = 6000;
int RTZ_LOCAL_MEDIA_PORT = 1935; /* rtmp push */
int RTMP_PUBLIC_PORT = 1935;
int RTMP_LOCAL_PORT = 1935;
const char *CERT_PEM = NULL;
const char *CERT_KEY = NULL;
static const char *CERT_PWD = NULL;

rtz_server_t *g_rtz_srv = NULL;

void signal_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
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

static void test_http_hooks(zl_loop_t *loop)
{
    http_hook_query(loop, "live", "", "", "", NULL, NULL);
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
    sigprocmask(SIG_BLOCK, &mask, NULL);

    llog_init(1, "gw.log");
    cfg_t *cfg = cfg_new();
    LLOG(LL_INFO, "starting...");

    ZK_HOST = cfg_get_text(cfg, "ZK_HOST", "");
    RTZ_LOCAL_IP = cfg_get_text(cfg, "RTZ_LOCAL_IP", "127.0.0.1");
    RTZ_PUBLIC_IP = cfg_get_text(cfg, "RTZ_PUBLIC_IP", RTZ_LOCAL_IP);
    RTZ_LOCAL_SIGNAL_PORT = cfg_get_int(cfg, "RTZ_LOCAL_SIGNAL_PORT", 443);
    RTZ_PUBLIC_SIGNAL_PORT = cfg_get_int(cfg, "RTZ_PUBLIC_SIGNAL_PORT", RTZ_LOCAL_SIGNAL_PORT);
    RTZ_LOCAL_MEDIA_PORT = cfg_get_int(cfg, "RTZ_LOCAL_MEDIA_PORT", 6000);
    RTZ_PUBLIC_MEDIA_PORT = cfg_get_int(cfg, "RTZ_PUBLIC_MEDIA_PORT", RTZ_LOCAL_MEDIA_PORT);
    RTMP_LOCAL_PORT = cfg_get_int(cfg, "RTMP_LOCAL_PORT", 1935);
    RTMP_PUBLIC_PORT = cfg_get_int(cfg, "RTMP_PUBLIC_PORT", RTMP_LOCAL_PORT);
    CERT_PEM = cfg_get_text(cfg, "CERT_PEM", "/root/mycert.pem");
    CERT_KEY = cfg_get_text(cfg, "CERT_KEY", "/root/mycert.key");
    LLOG(LL_INFO, "ZK_HOST=%s", ZK_HOST);
    LLOG(LL_INFO, "RTZ_LOCAL_IP:SIGNAL_PORT,MEDIA_PORT,RTMP_PORT=%s:%d,%d,%d",
         RTZ_LOCAL_IP, RTZ_LOCAL_SIGNAL_PORT, RTZ_LOCAL_MEDIA_PORT, RTMP_LOCAL_PORT);
    LLOG(LL_INFO, "RTZ_PUBLIC_IP:SIGNAL_PORT,MEDIA_PORT,RTMP_PORT=%s:%d,%d,%d",
         RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT, RTZ_PUBLIC_MEDIA_PORT, RTMP_PUBLIC_PORT);
    LLOG(LL_INFO, "CERT_PEM=%s", CERT_PEM);
    LLOG(LL_INFO, "CERT_KEY=%s", CERT_KEY);

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    dtls_srtp_init(CERT_PEM, CERT_KEY, CERT_PWD);
#if RTZ_SERVER_SSL
    tcp_ssl_init(CERT_PEM, CERT_KEY, CERT_PWD);
#endif

    //test_tsc();
	zl_loop_t *main_loop = zl_loop_new(1024);
    zl_loop_set_ct(main_loop);

    //test_http_hooks(main_loop);

    sigdelset(&mask, SIGPIPE);
    sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    zl_fd_ctl(main_loop, EPOLL_CTL_ADD, sfd, EPOLLIN, signal_event_handler, main_loop);

    g_rtz_srv = rtz_server_new(main_loop);
    rtz_server_bind(g_rtz_srv, RTZ_LOCAL_SIGNAL_PORT);
    rtz_server_start(g_rtz_srv);

    rtmp_server_t *rtmp_srv = rtmp_server_new(main_loop, g_rtz_srv);
    rtmp_server_bind(rtmp_srv, RTMP_LOCAL_PORT);
    rtmp_server_start(rtmp_srv);

    monitor_server_t *mon_srv = monitor_server_new(main_loop, g_rtz_srv, rtmp_srv);
    monitor_server_bind(mon_srv, RTMP_LOCAL_PORT + 50);
    monitor_server_start(mon_srv);

    if (strlen(ZK_HOST))
        start_zk_registry(main_loop);

    //start_zk_thread();

	//http_server_t *srv = http_server_new(loop);
 //   http_server_bind(srv, 5050);
 //   http_server_start(srv);

    while (!zl_loop_stopped(main_loop)) {
        zl_poll(main_loop, 100);
        //sleep(1);
	}

    if (strlen(ZK_HOST))
        stop_zk_registry();

    rtz_server_stop(g_rtz_srv);

    int i, n;
    for (i = 0; i < 5; ++i) {
        n = zl_poll(main_loop, 1000);
        if (n == 0)
            break;
    };

    monitor_server_del(mon_srv);
	rtmp_server_del(rtmp_srv);
    rtz_server_del(g_rtz_srv);

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
