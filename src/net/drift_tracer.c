#include "drift_tracer.h"
#include "macro_util.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

enum {
    DEFAULT_MAX_SAMPLES = 10 * 25,
    DEFAULT_MAX_DRIFT = 20,
};

struct drift_tracer_t {
    unsigned max_samples;
    int64_t max_drift;

    int64_t drift;
    int64_t over_drift;

    int64_t drift_sum;
    unsigned drift_samples;
};

drift_tracer_t *drift_tracer_new()
{
    drift_tracer_t *ctx = malloc(sizeof(drift_tracer_t));
    assert(ctx);
    memset(ctx, 0, sizeof(drift_tracer_t));
    ctx->max_samples = DEFAULT_MAX_SAMPLES;
    ctx->max_drift = DEFAULT_MAX_DRIFT;
    return ctx;
}
void drift_tracer_del(drift_tracer_t *ctx)
{
    free(ctx);
}
void drift_tracer_reset(drift_tracer_t *ctx)
{
    ctx->drift = 0;
    ctx->over_drift = 0;
    ctx->drift_sum = 0;
    ctx->drift_samples = 0;
}
void drift_tracer_set_config(drift_tracer_t *ctx, unsigned max_samples, int64_t max_drift)
{
    ctx->max_samples = max_samples;
    ctx->max_drift = max_drift;
}
int64_t drift_tracer_get_drift(drift_tracer_t *ctx)
{
    return ctx->drift;
}
int64_t drift_tracer_get_over_drift(drift_tracer_t *ctx)
{
    return ctx->over_drift;
}
bool drift_tracer_update(drift_tracer_t *ctx, int64_t driftval)
{
    ctx->drift_sum += driftval;
    ++ctx->drift_samples;
    //LLOG(LL_DEBUG, "#%04u drift=%"PRId64" max_samples=%u",
    //    ctx->drift_samples, driftval, ctx->max_samples);

    if (ctx->drift_samples >= ctx->max_samples) {
        ctx->over_drift = 0;

        ctx->drift = ctx->drift_sum / ctx->drift_samples;

        //LLOG(LL_DEBUG, "cur_drift=%"PRId64", max_drift=%"PRId64, ctx->drift, ctx->max_drift);

        ctx->drift_sum = 0;
        ctx->drift_samples = 0;

        if (ABS(ctx->drift) > ctx->max_drift) {
            ctx->over_drift = (ctx->drift < 0) ? -ctx->max_drift : ctx->max_drift;
            ctx->drift -= ctx->over_drift;
        }

        return true;
    }
    return false;
}
