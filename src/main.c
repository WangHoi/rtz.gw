#include "log.h"
//#include "gateway_server.h"
#include "event_loop.h"
#include "onvif_client.h"
#include "mpsc_queue.h"
//#include "rtsp_client.h"
//#include "rtmp_client.h"
//#include "gb_media_server.h"
//#include "sdp.h"
//#include "rtp_demux.h"
//#include "gb_logic.h"
//#include "sip_server.h"
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

/*
#include <oss_c_sdk/aos_http_io.h>
static const char* ALIYUN_ENDPOINT =  "oss-cn-beijing.aliyuncs.com";
static const char* ALIYUN_ACCESS_KEY_ID = "LTAIcn1595xRYyCD";
static const char* ALIYUN_ACCESS_KEY_SECRET = "sBErcaXkkJiiLG0IdyNLR9zTHP7L1T";
static const char* ALIYUN_BUCKET = "iot-media";

static void test_oss(void *arg);
*/
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

#if 0
rtp_demux_t *demux_ctx = NULL;
rtsp_client_t *pull_client = NULL;
rtmp_client_t *push_client = NULL;
int start_push = 0;

static void *sip_thread_entry(void *arg);
static void *media_thread_entry(void *arg);
static void cron_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);
static void test_timer_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata);

void video_handler(int64_t pts, int64_t ntp_ts, int64_t duration,
                   const nalu_part_t *units, size_t num_units,
                   void *udata)
{
    LLOG(LL_DEBUG, "video pts=%ld duration=%ld num_units=%ld",
         pts, duration, num_units);
    size_t i;
    for (i = 0; i < num_units; ++i) {
        LLOG(LL_DEBUG, "    size=%ld type=%d",
             units[i].size, (int)(units[i].data[0] & 0x1f));
        if (start_push)
            rtmp_client_send_video(push_client, ((pts / 90) & UINT32_MAX), units[i].data, units[i].size);
    }
}

void rtsp_connect_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "connect status %ld err=%s", status, strerror(-status));
}

void rtsp_describe_handler(zl_loop_t *loop, int64_t status, void *udata);
void rtsp_setup_handler(zl_loop_t *loop, int64_t status, void *udata);
void rtsp_play_handler(zl_loop_t *loop, int64_t status, void *udata);
void rtp_packet_handler(const char *data, int size, void *udata);
void rtsp_init_describe_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "open status %ld", status);
    if (status == 401)
        rtsp_client_describe(udata, rtsp_describe_handler);
}

void rtsp_describe_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "describe status %ld", status);
    rtsp_client_t *client = udata;
    const char *sdp_text = rtsp_client_get_sdp(client);
    sdp_t *sdp = sdp_new();
    int valid = sdp_parse(sdp, sdp_text);
    LLOG(LL_DEBUG, "parse sdp result %d", valid);
    if (valid) {
        sdp_track_t *t;
        t = sdp_get_video_track(sdp);
        if (t) {
            LLOG(LL_DEBUG, "track #%d type=%s control=%s codec=%s codec_param=%s"
                 " fmtp=%s sample_rate=%d rtp_payload=%d",
                 sdp_track_get_index(t), sdp_track_get_type(t), sdp_track_get_control(t),
                 sdp_track_get_codec(t), sdp_track_get_codec_param(t),
                 sdp_track_get_fmtp(t), sdp_track_get_sample_rate(t),
                 sdp_track_get_payload(t));

            rtsp_client_setup(client, sdp_track_get_control(t), rtsp_setup_handler);
        }
        t = sdp_get_audio_track(sdp);
        if (t) {
            LLOG(LL_DEBUG, "track #%d type=%s control=%s codec=%s codec_param=%s"
                 " fmtp=%s sample_rate=%d rtp_payload=%d",
                 sdp_track_get_index(t), sdp_track_get_type(t), sdp_track_get_control(t),
                 sdp_track_get_codec(t), sdp_track_get_codec_param(t),
                 sdp_track_get_fmtp(t), sdp_track_get_sample_rate(t),
                 sdp_track_get_payload(t));
        }
        demux_ctx = rtp_demux_new();
        rtp_demux_set_video_cb(demux_ctx, video_handler);
        rtp_demux_sdp(demux_ctx, sdp);
    }
}

void rtsp_setup_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "setup status %ld", status);
    if (status == 200) {
        rtsp_client_play(udata, rtsp_play_handler);
    }
}

void rtsp_play_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "play status %ld", status);
    
}

void rtp_packet_handler(const char *data, int size, void *udata)
{
    //LLOG(LL_TRACE, "got rtp packet size=%d %02hhx", size, data[12]);
    rtp_demux_input(demux_ctx, data, size);
}

void rtmp_video_handler(int64_t timestamp, const char *data, int size, void *udata);

void create_stream_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "createStream status %ld", status);
}

void release_stream_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "releaseStream status %ld", status);
}

void fcpublish_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "FCPublish status %ld", status);
}

void publish_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "publish status %ld", status);
    start_push = 1;
    LLOG(LL_TRACE, "start push...");
}

void rtmp_connect_handler(zl_loop_t *loop, int64_t status, void *udata)
{
    LLOG(LL_DEBUG, "rtmp connect status %ld", status);
    rtmp_client_t *client = udata;
    rtmp_client_set_video_packet_cb(client, rtmp_video_handler);
    rtmp_client_aconnect(client, NULL);
/*
    rtmp_client_create_stream(client, NULL);
    rtmp_client_play(client, NULL);
*/
    rtmp_client_release_stream(client, release_stream_handler);
    rtmp_client_fcpublish(client, fcpublish_handler);
    rtmp_client_create_stream(client, create_stream_handler);
    rtmp_client_publish(client, publish_handler);
}

void rtmp_video_handler(int64_t timestamp, const char *data, int size, void *udata)
{
    LLOG(LL_TRACE, "got rtmp video packet ts=%ld size=%d data=%02hhx",
         (long)timestamp, size, data[0]);
}

static void test_tsc()
{
    tsc_t *c = tsc_new(8);
    int i;
    uint8_t orig_ts, orig_start = 73;
    int64_t timestamp;
    srand48(0);
    for (i = 0; i < 256; ++i) {
        int8_t disturb = (int8_t)(mrand48() % 32);
        orig_ts = orig_start + (uint8_t)(i * 4) + (int8_t)disturb;
        timestamp = tsc_timestamp(c, orig_ts) ;
        LLOG(LL_TRACE, "orig=%hhu ts=%ld offset=%hhd fixed_ts=%ld", orig_ts, timestamp, disturb, timestamp - disturb);
    }
}

void test_onvif(void *arg)
{
    struct onvif_context *ctx = onvif_context_new();
    struct onvif_endpoint ep = {
        "http://172.20.226.130/onvif/device_service",
        "admin",
        "q1234567",
    };
    struct onvif_dev_info* dev_info;
    int ret;
    ret = onvif_GetDeviceInfo(ctx, &ep, &dev_info);
    onvif_context_del(ctx);
    if (ret == 0) {
        LLOG(LL_DEBUG, "sn='%s' manufacturer='%s' model='%s' hardwared_id='%s'",
             dev_info->serial_number, dev_info->manufacturer,
             dev_info->model, dev_info->hardware_id);
    } else {
        LLOG(LL_ERROR, "onvif error: %d.", ret);
    }
}

void after_cb(void *arg)
{
    LLOG(LL_DEBUG, "miao");
}
#endif

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

    //test_tsc();
	zl_loop_t *main_loop = zl_loop_new(1024);
    zl_loop_set_ct(main_loop);

    //test_http_hooks(main_loop);

    sigdelset(&mask, SIGPIPE);
    sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    zl_fd_ctl(main_loop, EPOLL_CTL_ADD, sfd, EPOLLIN, signal_event_handler, main_loop);

    //run_co(test_onvif, after_cb, NULL);

    //aos_http_io_initialize (NULL, 0);
    //run_co(test_oss, NULL, "000-test1");
    //run_co(test_oss, NULL, "000-test2");
    //run_co(test_oss, NULL, "000-test3");
    //run_co(test_oss, NULL, "000-test4");
    //run_co(test_oss, NULL, "000-test5");

    //test_oss("000-test1");
    //test_oss("000-test2");
    //test_oss("000-test3");
    //test_oss("000-test4");
    //test_oss("000-test5");

    /*
    gb_logic_t *logic = gb_logic_new(main_loop);
    zl_loop_t *sip_loop = zl_loop_new(1024);
    sip_server_t *sip_srv = sip_server_new(sip_loop, logic, "172.20.226.86", "34120000002000000001", 1);
    pthread_t sip_tid;
    pthread_create(&sip_tid, NULL, sip_thread_entry, sip_srv);

    zl_loop_t *media_loop = zl_loop_new(1024);
    gb_media_server_t *media_srv = gb_media_server_new(media_loop, logic);
    gb_media_server_bind(media_srv, 9010);
    pthread_t media_tid;
    pthread_create(&media_tid, NULL, media_thread_entry, media_srv);

    gb_add_media_server(logic, media_srv);
    gb_logic_start(logic);
    */

    rtz_server_t *rtz_srv = rtz_server_new(main_loop);
    rtz_server_bind(rtz_srv, RTZ_LOCAL_SIGNAL_PORT);
    rtz_server_start(rtz_srv);

    rtmp_server_t *rtmp_srv = rtmp_server_new(main_loop, rtz_srv);
    rtmp_server_bind(rtmp_srv, RTMP_LOCAL_PORT);
    rtmp_server_start(rtmp_srv);

    monitor_server_t *mon_srv = monitor_server_new(main_loop, rtz_srv, rtmp_srv);
    monitor_server_bind(mon_srv, RTMP_LOCAL_PORT + 50);
    monitor_server_start(mon_srv);

    if (strlen(ZK_HOST))
        start_zk_thread();

    //start_zk_thread();

	//http_server_t *srv = http_server_new(loop);
 //   http_server_bind(srv, 5050);
 //   http_server_start(srv);

#if 0
    pull_client = rtsp_client_new(loop);
    rtsp_client_set_uri(pull_client, "rtsp://172.20.226.24");
    rtsp_client_set_user(pull_client, "admin");
    rtsp_client_set_password(pull_client, "Q1234567");
    rtsp_client_connect(pull_client, rtsp_connect_handler);
    rtsp_client_describe(pull_client, rtsp_init_describe_handler);
    rtsp_client_set_packet_cb(pull_client, rtp_packet_handler);

    push_client = rtmp_client_new(loop);
    rtmp_client_set_uri(push_client, "rtmp://172.20.226.49/live/stream");
    rtmp_client_connect(push_client, rtmp_connect_handler);

    int cron_fd = zl_timerfd_new();
    zl_timerfd_settime(cron_fd, 2000, 0);
    zl_fd_ctl(loop, EPOLL_CTL_ADD, cron_fd, EPOLLIN, test_timer_handler, NULL);
#endif
    while (!zl_loop_stopped(main_loop)) {
        zl_poll(main_loop, 100);
        //sleep(1);
	}

    if (strlen(ZK_HOST))
        stop_zk_thread();

    rtz_server_stop(rtz_srv);

    int i, n;
    for (i = 0; i < 5; ++i) {
        n = zl_poll(main_loop, 1000);
        if (n == 0)
            break;
    };

    monitor_server_del(mon_srv);
	rtmp_server_del(rtmp_srv);
    rtz_server_del(rtz_srv);

    zl_fd_ctl(main_loop, EPOLL_CTL_DEL, sfd, 0, NULL, NULL);
    close(sfd);

    zl_loop_del(main_loop);

    dtls_srtp_cleanup();
    EVP_cleanup();
    ERR_free_strings();

    cfg_del(cfg);
    llog_cleanup();
	return 0;
}

#if 0
void cron_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    zl_timerfd_read(fd);
    rtsp_client_cron(loop);
}

void test_timer_handler(zl_loop_t* loop, int fd, uint32_t events, void *udata)
{
    zl_timerfd_read(fd);
    zl_fd_ctl(loop, EPOLL_CTL_DEL, fd, 0, NULL, NULL);
    //start_push = 1;
    //LLOG(LL_TRACE, "start push...");
}

void *sip_thread_entry(void *arg)
{
    sip_server_t *srv = arg;
    zl_loop_t *loop = sip_server_get_loop(srv);
    zl_loop_set_ct(loop);
    sip_server_start(srv);
    while (1) {
        sip_server_poll(srv);
        zl_poll(loop, 0);
    }
    zl_loop_set_ct(NULL);
    return NULL;
}

void *media_thread_entry(void *arg)
{
    gb_media_server_t *srv = arg;
    zl_loop_t *loop = gb_media_server_get_loop(srv);
    zl_loop_set_ct(loop);
    gb_media_server_start(srv);
    while (1) {
        zl_poll(loop, 0);
    }
    zl_loop_set_ct(NULL);
    return NULL;
}
#endif

/*
#include <oss_c_sdk/oss_api.h>
#include <oss_c_sdk/aos_status.h>
#include <oss_c_sdk/aos_string.h>

static oss_request_options_t* oss_create_default_request_options ()
{
    aos_pool_t *pool = NULL;
    aos_pool_create (&pool, NULL);
    if (pool == NULL) {
        return NULL;
    }
    oss_request_options_t *option = oss_request_options_create (pool);
    if (option == NULL) {
        return NULL;
    }
    option->config = oss_config_create (pool);
    aos_str_set (&option->config->endpoint, ALIYUN_ENDPOINT);
    aos_str_set (&option->config->access_key_id, ALIYUN_ACCESS_KEY_ID);
    aos_str_set (&option->config->access_key_secret, ALIYUN_ACCESS_KEY_SECRET);
    option->config->is_cname = 0;
    option->ctl = aos_http_controller_create(pool, 0);

    return option;
}

static const char g_str[10 * 1024 * 1024] = {};

void test_oss(void *arg)
{
    aos_string_t bucket;
    aos_string_t object;
    aos_string_t prefix;
    oss_request_options_t *options;
    aos_status_t *ret;
    aos_table_t *headers = NULL;
    aos_table_t *resp_headers = NULL;
    aos_list_t buffer;
    aos_buf_t *content = NULL;

    options = oss_create_default_request_options ();

    aos_str_set(&bucket, ALIYUN_BUCKET);
    aos_str_set(&object, (const char*)arg);

    headers = aos_table_make(options->pool, 1);
    apr_table_set(headers, "x-oss-meta-author", "oss");

    aos_list_init(&buffer);
    content = aos_buf_pack(options->pool, g_str, sizeof(g_str));
    aos_list_add_tail(&content->node, &buffer);

    LLOG(LL_TRACE, "before put object %s", (const char*)arg);
    ret = oss_put_object_from_buffer(options, &bucket, &object,
                                     &buffer, headers, &resp_headers);
    LLOG(LL_TRACE, "after put object %s, ret=%d", (const char*)arg, ret ? ret->code : -1);

    aos_pool_destroy(options->pool);
}
*/
