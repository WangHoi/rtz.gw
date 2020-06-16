#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct drift_tracer_t drift_tracer_t;

drift_tracer_t *drift_tracer_new();
void drift_tracer_del(drift_tracer_t *ctx);
void drift_tracer_reset(drift_tracer_t *ctx);
void drift_tracer_set_config(drift_tracer_t *ctx, unsigned max_samples, int64_t max_drift);
int64_t drift_tracer_get_drift(drift_tracer_t *ctx);
int64_t drift_tracer_get_over_drift(drift_tracer_t *ctx);
// @drift: encoder_clock - reference_clock
bool drift_tracer_update(drift_tracer_t *ctx, int64_t drift);
