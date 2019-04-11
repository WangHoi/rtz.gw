#pragma once
#include <sched.h>
#include <unistd.h>
#include "log.h"

inline int set_cpu_scheduler_fifo_ct()
{
    struct sched_param p = {
        .sched_priority = 99
    };
    return sched_setscheduler(0, SCHED_FIFO, &p);
}

inline int set_cpu_affinity_ct(int core)
{
    cpu_set_t s;
    CPU_ZERO(&s);
    CPU_SET(core, &s);
    return sched_setaffinity(0, sizeof(cpu_set_t), &s);
}

inline int get_cpu_count()
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}
