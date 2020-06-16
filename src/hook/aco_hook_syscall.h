#pragma once

typedef void (*co_cb)(void*);
void run_co(co_cb func, co_cb after_func, void *udata);
void init_aco(int hook_syscall);
