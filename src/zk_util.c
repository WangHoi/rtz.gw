#include "zk_util.h"
#include "sbuf.h"
#include "event_loop.h"
#include "log.h"
#include "net/rtz_server.h"
#include <zookeeper/zookeeper.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

/*
流媒体服务器向zookeeper的注册信息
{
    "mode": 2,
    "public_host": "ip:port",
    "local_host": "ip:port",
    "origin_host": "ip:port",
    "load": 10
}

mode:
    1、源节点， 作为推流地址
    2、边缘节点，作为取流地址
注：a、目前只在直播时候考虑推流到源节点，从边缘节点取流。其余情况下都向源节点推流和取流
    b、考虑到向前兼容流媒体服务器注册信息，当没有mode字段的时候，该节点即使源节点也是边缘节点

public_host: 外网地址
local_host： 内网地址
origin_host：
    a、当该节点为源节点时候， 该地址同内网地址
    b、当该节点为边缘节点时候， 该地址为边缘节点对应的源节点的内网地址

load： 负载信息，流媒体服务器的推流和取流路数

在zk中注册的目录结构如下：
1、在/avideo/srs/load/下，注册源节点的信息。
2、在/avideo/srs/edge/ip:port/srs/下，注册srs边缘节点的信息， ip:port为边缘节点对应的源节点地址，即边缘节点注册信息中origin_host的值。
3、在/avideo/srs/edge/ip:port/rtz/下，注册rtc服务器的信息。

*/

extern const char *ZK_HOST;
extern const char *RTZ_PUBLIC_IP;
extern const char *RTZ_LOCAL_IP;
extern int RTZ_PUBLIC_SIGNAL_PORT;
extern int RTMP_PUBLIC_PORT;
extern int RTMP_LOCAL_PORT;
extern const char *ORIGIN_HOST;

extern rtz_server_t *g_rtz_srv;

static zl_loop_t *zloop = NULL;
static zhandle_t *handle = NULL;
static volatile int connected = 0;
static int ztimer = -1;
static sbuf_t *rtz_real_path = NULL;
static const char *RTZ_ORIGIN_SERVICE_NAME = "/avideo/rtz/load/";
static const char *RTZ_EDGE_SERVICE_NAME_PREFIX = "/avideo/srs/edge/";
static const int RECV_TIMEOUT_MSECS = 30000;
static const int UPDATE_TIMEOUT_MSECS = 10000;

static char rtz_edge_service_name[1024];

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
    int edge = (ORIGIN_HOST != NULL);
    if (edge) {
        snprintf(rtz_edge_service_name, sizeof(rtz_edge_service_name),
                 "%s%s/rtz/", RTZ_EDGE_SERVICE_NAME_PREFIX, ORIGIN_HOST);
        zk_mkdir(handle, rtz_edge_service_name, rtz_real_path,
                 RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
                 RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
    } else {
        zk_mkdir(handle, RTZ_ORIGIN_SERVICE_NAME, rtz_real_path,
                 RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
                 RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
    }
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
    if (ORIGIN_HOST) {
        snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\","
                 " \"origin_host\":\"%s\", \"mode\":2, \"load\": %d}",
                 public_ip, public_port, local_ip, local_port, ORIGIN_HOST, 0);
    } else {
        snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\","
                 " \"origin_host\":\"%s:%d\", \"mode\":1, \"load\": %d}",
                 public_ip, public_port, local_ip, local_port, local_ip, local_port, 0);
    }
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
    if (ORIGIN_HOST) {
        snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\","
                 " \"origin_host\":\"%s\", \"mode\":2, \"load\": %d}",
                 public_ip, public_port, local_ip, local_port, ORIGIN_HOST, rtz_get_stats(g_rtz_srv));
    } else {
        snprintf(text, sizeof(text), "{\"public_host\": \"%s:%d\",\"local_host\": \"%s:%d\","
                 " \"origin_host\":\"%s:%d\", \"mode\":1, \"load\": %d}",
                 public_ip, public_port, local_ip, local_port, local_ip, local_port, rtz_get_stats(g_rtz_srv));
    }
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
