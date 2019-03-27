#include "watchdog.h"
#if WITH_SYSTEMD
#include "event_loop.h"
#include "log.h"
#include <systemd/sd-daemon.h>
#include <inttypes.h>
#include <stddef.h>
static int timer = -1;
static zl_loop_t *loop = NULL;
static void watchdog_timeout_handler(zl_loop_t *loop, int timer, void *udata);
void start_watchdog(zl_loop_t *l)
{
    loop = l;
    uint64_t usec;
    int ret = sd_watchdog_enabled(0, &usec);
    if (ret > 0) {
        long timeout = usec / 1000 / 2;
        LLOG(LL_INFO, "start watchdog, report interval %ld ms", timeout);
        timer = zl_timer_start(loop, timeout, timeout, watchdog_timeout_handler, NULL);
    } else {
        LLOG(LL_WARN, "watchdog disabled");
    }
}
void stop_watchdog()
{
    if (timer != -1) {
        LLOG(LL_INFO, "stop watchdog");
        zl_timer_stop(loop, timer);
        timer = -1;
    }
}
void watchdog_timeout_handler(zl_loop_t *loop, int timer, void *udata)
{
    sd_notify(0, "WATCHDOG=1");
}
#else
void start_watchdog(zl_loop_t *loop)
{

}
void stop_watchdog()
{

}
#endif
