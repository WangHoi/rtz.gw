#include "log.h"
#include "macro_util.h"
#include "mpsc_queue.h"
#include "sbuf.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/eventfd.h>
#include <time.h>
#include <pthread.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#if WITH_COLOR
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#else
#define ANSI_COLOR_RED     ""
#define ANSI_COLOR_GREEN   ""
#define ANSI_COLOR_YELLOW  ""
#define ANSI_COLOR_BLUE    ""
#define ANSI_COLOR_MAGENTA ""
#define ANSI_COLOR_CYAN    ""
#define ANSI_COLOR_RESET   ""
#endif

enum {
    LOG_MSG_DATA = 1,
    LOG_MSG_EXIT = 2,
    LOG_MSG_FLUSH = 4,
};

enum {
    INITIAL_BUFSZ = 2000,
};

static const char *LL_LEVEL_NAMES[] = {
	ANSI_COLOR_MAGENTA " FATAL " ANSI_COLOR_RESET,
    ANSI_COLOR_RED " ERROR " ANSI_COLOR_RESET,
    ANSI_COLOR_YELLOW " WARN " ANSI_COLOR_RESET,
	" ", // INFO
	" ", // DEBUG
	" ", // TRACE
};
_Static_assert(ARRAY_SIZE(LL_LEVEL_NAMES) == LL_TRACE + 1, "Invalid LL_LEVEL_NAMES[] size");

static enum LogLevel max_log_lvl = LL_TRACE;
static pthread_t llog_pid = 0;
static struct mpsc_queue *mq = NULL;
static int llog_evt_fd = -1;
static void *llog_thread(void* arg);

static inline void llog_notify()
{
    uint64_t i = 1;
    UNUSED(write(llog_evt_fd, &i, sizeof(i)));
}

static inline void llog_wait()
{
    uint64_t i;
    UNUSED(read(llog_evt_fd, &i, 8));
}

void llog_set_level(enum LogLevel lvl)
{
	max_log_lvl = lvl;
}

void llog_fmt(const char* filename, int fileline, const char* funcname, enum LogLevel lvl, const char* fmt, ...) 
{
	if (lvl > max_log_lvl)
		return;

    struct mpsc_msg *m = mpsc_reserve(mq);
    if (!m)
        return;

    struct timespec tp;
    time_t tt;
    struct tm t;

    clock_gettime(CLOCK_REALTIME, &tp);
    tt = (time_t)tp.tv_sec;
    localtime_r(&tt, &t);
    const char *short_filename = strrchr(filename, '/');
	short_filename = short_filename ? (short_filename + 1) : filename;

    sbuf_t *b = sbuf_new1(INITIAL_BUFSZ);
    sbuf_appendf(b, "%02d-%02d %02d:%02d:%02d.%03d %s:%d%s",
                 t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min,
                 t.tm_sec, (int)(tp.tv_nsec / 1000000),
	             short_filename, fileline, LL_LEVEL_NAMES[lvl]);
    va_list ap;
    va_start(ap, fmt);
    sbuf_appendv(b, fmt, ap);
	va_end(ap);

    sbuf_appendc(b, '\n');

    m->u64[0] = (uint64_t)b;
    mpsc_commit(m, LOG_MSG_DATA);
    llog_notify();
}

void llog_raw(const char *msg, int append_lf)
{
    struct mpsc_msg *m = mpsc_reserve(mq);
    if (!m)
        return;
    sbuf_t *b = sbuf_strdup(msg);
    if (append_lf)
        sbuf_appendc(b, '\n');
    m->u64[0] = (uint64_t)b;
    mpsc_commit(m, LOG_MSG_DATA);
    llog_notify();
}

void llog_flush()
{
    struct mpsc_msg *m = mpsc_reserve(mq);
    while (!m) {
        pthread_yield();
        m = mpsc_reserve(mq);
    }
    volatile int flushed = 0;
    m->u64[0] = (uintptr_t)&flushed;
    mpsc_commit(m, LOG_MSG_FLUSH);
    llog_notify();
    while (!flushed) {
        usleep(100 * 1000);
    }
}

void llog_init()
{
    llog_evt_fd = eventfd(0, EFD_CLOEXEC);
    mq = mpsc_queue_new(16);
    int ret = pthread_create(&llog_pid, NULL, llog_thread, NULL);
    assert(!ret);
}

void llog_cleanup()
{
    struct mpsc_msg *m = mpsc_reserve(mq);
    while (!m) {
        pthread_yield();
        m = mpsc_reserve(mq);
    }
    mpsc_commit(m, LOG_MSG_EXIT);
    llog_notify();
    pthread_join(llog_pid, NULL);
    mpsc_queue_del(mq);
    if (llog_evt_fd != -1)
        close(llog_evt_fd);
}

void *llog_thread(void *arg)
{
    while (1) {
        struct mpsc_msg *m = mpsc_peek(mq);
        while (m) {
            if (m->id == LOG_MSG_DATA) {
                sbuf_t *b = (void*)m->u64[0];
                UNUSED(write(STDOUT_FILENO, b->data, b->size));
                sbuf_del(b);
            } else if (m->id == LOG_MSG_EXIT) {
                pthread_exit(NULL);
            } else if (m->id == LOG_MSG_FLUSH) {
                volatile int *p = (volatile int*)m->u64[0];
                *p = 1;
            }
            mpsc_consume(mq, m);
            m = mpsc_peek(mq);
        }
        llog_wait();
    }
}
