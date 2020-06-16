#pragma once

typedef struct cfg_t cfg_t;
cfg_t *cfg_new();
void cfg_del(cfg_t *cfg);
const char *cfg_get_text(cfg_t *cfg, const char *name, const char *def);
int cfg_get_bool(cfg_t *cfg, const char *name, int def);
int cfg_get_int(cfg_t *cfg, const char *name, int def);
