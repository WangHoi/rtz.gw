#pragma once
#include <stdint.h>

typedef struct tsc_t tsc_t;

tsc_t *tsc_new(int bits, int64_t gap_threhold, int64_t gap_fix_step);
void tsc_del(tsc_t *c);
void tsc_reset(tsc_t *c);
int64_t tsc_timestamp(tsc_t *c, int64_t timestamp);
