#include "timestamp.h"
#include "log.h"
#include "macro_util.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

struct tsc_t {
    int64_t start_timestamp;        /* bits width */
    int64_t start_wrap_timestamp;   /* bits width */
    int64_t end_wrap_timestamp;     /* bits width */
    int64_t last_nts;               /* 64-bit normalized timestamp */
    int64_t gap_threhold;
    int64_t gap_fix_step;
    int bits;
    int wrap;
    int64_t wrap_counter;
};

tsc_t *tsc_new(int bits, int64_t gap_threhold, int64_t gap_fix_step)
{
    assert(bits <= 48 && bits >= 8);
    tsc_t *c = malloc(sizeof(tsc_t));
    memset(c, 0, sizeof(tsc_t));
    c->start_timestamp = INT64_MIN;
    c->last_nts = INT64_MIN;
    c->gap_threhold = gap_threhold;
    c->gap_fix_step = gap_fix_step;
    c->wrap = 0;
    c->bits = bits;
    c->end_wrap_timestamp = (1ll << (bits - 2));
    c->start_wrap_timestamp = (1ll << bits) - c->end_wrap_timestamp;
    return c;
}

void tsc_del(tsc_t *c)
{
    free(c);
}

void tsc_reset(tsc_t *c)
{
    c->start_timestamp = INT64_MIN;
    c->wrap = 0;
    c->wrap_counter = 0;
}

int64_t tsc_timestamp(tsc_t *c, int64_t timestamp)
{
    if (c->start_timestamp == INT64_MIN)
        c->start_timestamp = timestamp;
    if (timestamp > c->start_wrap_timestamp && c->wrap == 0) {
        LLOG(LL_TRACE, "start wrap %ld %ld", timestamp, c->start_wrap_timestamp);
        c->wrap = 1;
    } else if (timestamp <= c->end_wrap_timestamp && c->wrap == 1) {
        LLOG(LL_TRACE, "cross wrap %ld %ld", timestamp, c->end_wrap_timestamp);
        c->wrap = 2;
    } else if (timestamp > c->end_wrap_timestamp && timestamp <= c->start_wrap_timestamp && c->wrap == 2) {
        LLOG(LL_TRACE, "end wrap %ld %ld %ld", timestamp, c->end_wrap_timestamp, c->wrap_counter + 1);
        c->wrap = 0;
        ++c->wrap_counter;
    }
    if (c->wrap && timestamp <= c->end_wrap_timestamp)
        timestamp += (1ll << c->bits);
    int64_t nts = timestamp + (c->wrap_counter << c->bits) - c->start_timestamp;
    if (c->last_nts != INT64_MIN && (ABS(nts - c->last_nts) > c->gap_threhold)) {
        LLOG(LL_ERROR, "fix gap %"SCNi64, nts - c->last_nts);
        nts = c->last_nts + c->gap_fix_step;
        c->start_timestamp = timestamp - nts;
        c->wrap = (timestamp > c->start_wrap_timestamp) ? 1 : 0;
        c->wrap_counter = 0;
    }
    c->last_nts = nts;
    return nts;
}
