#pragma once
typedef struct zl_loop_t zl_loop_t;

void start_watchdog(zl_loop_t *loop);
void stop_watchdog();
