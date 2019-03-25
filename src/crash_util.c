#include "crash_util.h"
#include "log.h"
#include <signal.h>
#include <unwind.h>
#include <libunwind.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#define	BACKTRACE_DEPTH	256
#define	NULLSTR	"<NULL>"

static inline void print_str(const char *str)
{
    if (str == NULL) {
        llog_raw(NULLSTR, 0);
    } else {
        llog_raw(str, 0);
    }
}

static void print_unw_error(const char *fun, int error)
{
    print_str(fun);
    print_str(": ");
    print_str(unw_strerror(error));
    print_str("\n");
}

static int print_stack_trace(ucontext_t *context)
{
    unw_cursor_t cursor;
    unw_word_t backtrace[BACKTRACE_DEPTH];
    unw_word_t ip, off;
    char buf[1024];
    unsigned int i, level;
    int ret;

    if ((ret = unw_init_local(&cursor, context)) != 0) {
        print_unw_error("unw_init_local", ret);
        return (1);
    }

    print_str("   thread frame     IP       function\n");
    level = 0;
    ret = 0;
    for (;;) {
        char name[128];

        if (level >= BACKTRACE_DEPTH)
            break;
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        backtrace[level] = ip;

        /*
         * Print the function name and offset.
         */
        ret = unw_get_proc_name(&cursor, name, sizeof(name), &off);
        if (ret == 0) {
            snprintf(buf, sizeof(buf),
                     "  [%ld] %2d: 0x%09" PRIxPTR
                     ": %s()+0x%lx\n",
                     syscall(SYS_gettid), level, ip, name,
                     (uintptr_t)off);
        } else {
            snprintf(buf, sizeof(buf),
                     "  [%ld] %2d: 0x%09" PRIxPTR
                     ": <unknown>\n", syscall(SYS_gettid),
                     level, ip);
        }
        print_str(buf);
        level++;
        ret = unw_step(&cursor);
        if (ret <= 0)
            break;
    }
    if (ret < 0) {
        print_unw_error("unw_step_ptr", ret);
        return (1);
    }
    print_str("\nBacktrace:");
    for (i = 0; i < level; i++) {
        snprintf(buf, sizeof(buf), " 0x%"PRIxPTR, backtrace[i]);
        print_str(buf);
    }
    print_str("\n");
    return (0);
}

static void segfault_handler(int sig, siginfo_t *info, void *ctx)
{
    struct sigaction sa;
    ucontext_t *uap = ctx;
    char buf[16];

    print_str("Caught signal ");
    snprintf(buf, sizeof(buf), "%d (", sig);
    print_str(buf);
    print_str(strsignal(sig));
    print_str(") in program ");
    print_str("rtz.gw"); /* getprogname() */
    snprintf(buf, sizeof(buf), " [%d]\n", getpid());
    print_str(buf);
    print_str("\n");

    print_stack_trace(uap);
    llog_flush();

    /*
     * Restore the original signal handler and propagate the signal.
     */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(sig, &sa, NULL);
    kill(getpid(), sig);
}

void install_crash_handler()
{
    struct sigaction sa;
    const char *signals;
    int error;

    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = &segfault_handler;
    sa.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGSYS, &sa, NULL);
}
