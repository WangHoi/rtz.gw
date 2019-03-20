#include "zk_util.h"
#include "sbuf.h"
#include "event_loop.h"
#include "log.h"
#include "net/rtz_server.h"
#include <zookeeper/zookeeper.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

extern const char *ZK_HOST;
extern const char *RTZ_PUBLIC_IP;
extern const char *RTZ_LOCAL_IP;
extern int RTZ_PUBLIC_SIGNAL_PORT;
extern int RTMP_PUBLIC_PORT;
extern int RTMP_LOCAL_PORT;

extern rtz_server_t *g_rtz_srv;

static zl_loop_t *zloop = NULL;
static zhandle_t *handle = NULL;
static volatile int connected = 0;
static int ztimer = -1;
static sbuf_t *rtz_real_path = NULL;
static const char *RTZ_SERVICE_NAME = "/avideo/mse/load/";
static const char *RTMP_SERVICE_NAME = "/avideo/srs/load/";
static const int RECV_TIMEOUT_MSECS = 30000;
static const int UPDATE_TIMEOUT_MSECS = 10000;

static void zk_watch(zhandle_t *zzh, int type, int state, const char *path, void* ctx);
static void zk_mkdir(zhandle_t *handle, const char *service_name, sbuf_t *real_path,
                     const char *public_ip, int public_port,
                     const char *local_ip, int local_port);
static void zk_update(zhandle_t *handle, const char *real_path,
                      const char *public_ip, int public_port,
                      const char *local_ip, int local_port);
static void zk_timeout_handler(zl_loop_t *loop, int id, void *udata);

static void zk_log_handler(const char *message);

void start_zk_registry(zl_loop_t *loop)
{
    zloop = loop;
    rtz_real_path = sbuf_new();
    handle = zookeeper_init2(ZK_HOST, &zk_watch, RECV_TIMEOUT_MSECS, NULL, (void*)&connected, 0, zk_log_handler);
    zk_mkdir(handle, RTZ_SERVICE_NAME, rtz_real_path,
             RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
             RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
    ztimer = zl_timer_start(loop, UPDATE_TIMEOUT_MSECS, UPDATE_TIMEOUT_MSECS, zk_timeout_handler, NULL);
}

void stop_zk_registry()
{
    zl_timer_stop(zloop, ztimer);
    ztimer = -1;
    sbuf_del(rtz_real_path);
    rtz_real_path = NULL;
    if (handle) {
        zookeeper_close(handle);
        handle = NULL;
    }
    connected = 0;
}

void zk_mkdir(zhandle_t *handle, const char *service_name, sbuf_t *real_path,
              const char *public_ip, int public_port, const char *local_ip, int local_port)
{
    int ret;
    sbuf_t *mid_node = sbuf_new();
    const char *pos = strchr(service_name + 1, '/');
    while (pos) {
        sbuf_strncpy(mid_node, service_name, pos - service_name);

        struct Stat stat;
        ret = zoo_exists(handle, mid_node->data, 0, &stat);
        if (ret == ZNONODE) {
            char realpath[1024] = { 0 };
            ret = zoo_create(handle, mid_node->data, mid_node->data, mid_node->size,
                             &ZOO_OPEN_ACL_UNSAFE, 0, realpath, sizeof(realpath) - 1);
            if (ret != ZOK) {
                LLOG(LL_ERROR, "create mid node path '%s', real path '%s' failed!", mid_node->data, realpath);
                break;
            } else {
                LLOG(LL_TRACE, "create mid node path '%s', real path '%s' ok!", mid_node->data, realpath);
            }
        }
        pos = strchr(pos + 1, '/');
    }
    char realpath[1024] = { 0 };
    char text[1024];
    snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\", \"load\": %d}",
             public_ip, public_port, local_ip, local_port, 0);
    ret = zoo_create(handle, service_name, text, strlen(text), &ZOO_OPEN_ACL_UNSAFE,
                     ZOO_EPHEMERAL | ZOO_SEQUENCE, realpath, sizeof(realpath) - 1);
    if (ret == ZOK) {
        sbuf_strcpy(real_path, realpath);
        LLOG(LL_TRACE, "publish ok, node path '%s', real path '%s'", service_name, realpath);
    } else {
        LLOG(LL_ERROR, "create tmp node path '%s', real path '%s' failed!", service_name, realpath);
    }
    sbuf_del(mid_node);
}


void zk_watch(zhandle_t *zzh, int type, int state, const char *path, void* ctx)
{
    volatile int *pconnected = ctx;
    if (type == ZOO_SESSION_EVENT) {
        if (state == ZOO_CONNECTED_STATE) {
            LLOG(LL_TRACE, "connected");
            *pconnected = 1;
        } else if (state == ZOO_EXPIRED_SESSION_STATE) {
            LLOG(LL_TRACE, "disconnected");
            *pconnected = 0;
        } else {
            LLOG(LL_WARN, "ignore zookeeper event type=%d state=%d", type, state);
        }
    }
}

void zk_update(zhandle_t *handle, const char *real_path,
               const char *public_ip, int public_port,
               const char *local_ip, int local_port)
{
    char text[1024];
    unsigned short PORT = 6060;
    snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\", \"load\": %d}",
             public_ip, public_port, local_ip, local_port, rtz_get_stats(g_rtz_srv));
    int ret = zoo_set(handle, real_path, text, strlen(text), -1);
    if (ret != ZOK) {
        LLOG(LL_ERROR, "zoo_set error %d", ret);
    } else {
        //LLOG(LL_TRACE, "zoo_set ok");
    }
}

void zk_timeout_handler(zl_loop_t *loop, int id, void *udata)
{
    if (connected)
        zk_update(handle, rtz_real_path->data,
                  RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
                  RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
}

void zk_log_handler(const char *message)
{
    llog_raw(message);
}
