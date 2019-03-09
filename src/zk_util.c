#include "zk_util.h"
#include "sbuf.h"
#include "event_loop.h"
#include "log.h"
#include <zookeeper/zookeeper.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

extern const char *ZK_HOST;
extern const char *RTZ_PUBLIC_IP;
extern const char *RTZ_LOCAL_IP;
extern int RTZ_PUBLIC_SIGNAL_PORT;
extern int RTMP_PUBLIC_PORT;
extern int RTMP_LOCAL_PORT;

pthread_t tid;
volatile int started = 0;

static void *zk_thread_entry(void *);
static void zk_watch(zhandle_t *zzh, int type, int state, const char *path, void* ctx);
static void zk_mkdir(zhandle_t *handle, const char *service_name, sbuf_t *real_path,
                     const char *public_ip, int public_port,
                     const char *local_ip, int local_port);
static void zk_update(zhandle_t *handle, const char *real_path,
                      const char *public_ip, int public_port,
                      const char *local_ip, int local_port);

void start_zk_thread()
{
    pthread_create(&tid, NULL, zk_thread_entry, NULL);
    while (!started)
        pthread_yield();
}

void stop_zk_thread()
{
    if (!started)
        return;
    started = 0;
    pthread_join(tid, NULL);
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

void *zk_thread_entry(void *arg)
{
    const char *RTZ_SERVICE_NAME = "/avideo/mse/load/";
    const char *RTMP_SERVICE_NAME = "/avideo/srs/load/";
    const int RECV_TIMEOUT_MSECS = 30000;
    int connected = 0, ret;

    zhandle_t *handle = NULL;
    sbuf_t *rtz_real_path = sbuf_new();
    sbuf_t *rtmp_real_path = sbuf_new();
    started = 1;

    handle = zookeeper_init(ZK_HOST, &zk_watch, RECV_TIMEOUT_MSECS, NULL, &connected, 0);
    zk_mkdir(handle, RTZ_SERVICE_NAME, rtz_real_path,
             RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
             RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
    //zk_mkdir(handle, RTMP_SERVICE_NAME, rtmp_real_path);

    long long update_ts = zl_timestamp();
    //zk_update(handle, rtz_real_path->data);
    while (started) {
        sleep(1);
        long long ts = zl_timestamp();
        if (ts > update_ts + 30000) {
            update_ts = ts;
            zk_update(handle, rtz_real_path->data,
                      RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT,
                      RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
            /*
            zk_update(handle, rtmp_real_path->data,
                      RTZ_PUBLIC_IP, RTMP_PUBLIC_PORT,
                      RTZ_LOCAL_IP, RTMP_LOCAL_PORT);
                      */
        }
    }

    zookeeper_close(handle);
    sbuf_del(rtz_real_path);
    sbuf_del(rtmp_real_path);
    return NULL;
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
             public_ip, public_port, local_ip, local_port, 0);
    int ret = zoo_set(handle, real_path, text, strlen(text), -1);
    if (ret != ZOK) {
        LLOG(LL_ERROR, "zoo_set error %d", ret);
    } else {
        //LLOG(LL_TRACE, "zoo_set ok");
    }
}
