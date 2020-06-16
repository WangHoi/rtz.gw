#include "cfg_util.h"
#include "list.h"
#include <stdlib.h>
#include <string.h>

struct cfg_memblock {
    void *ptr;
    struct hlist_node link;
};

struct cfg_t {
    struct hlist_head memblk_list;
};

cfg_t *cfg_new()
{
    cfg_t *cfg = malloc(sizeof(cfg_t));
    INIT_HLIST_HEAD(&cfg->memblk_list);
    return cfg;
}

void cfg_del(cfg_t *cfg)
{
    struct hlist_node *l, *tmp;
    struct cfg_memblock *b;
    hlist_for_each_entry_safe(b, l, tmp, &cfg->memblk_list, link) {
        free(b);
    }
    free(cfg);
}

const char *cfg_get_text(cfg_t *cfg, const char *name, const char *def)
{
    char *env_value = getenv(name);
    char *tmp = env_value ?: (char*)def;
    if (!tmp)
        return NULL;
    tmp = strdup(tmp);
    struct cfg_memblock *b = malloc(sizeof(struct cfg_memblock));
    b->ptr = tmp;
    hlist_add_head(&b->link, &cfg->memblk_list);
    return tmp;
}

int cfg_get_bool(cfg_t *cfg, const char *name, int def)
{
    char *env_value = getenv(name);
    if (!env_value)
        return def;
    char ch = env_value[0];
    return (ch == 't') || (ch == 'o')
        || (ch == '1') || (ch == 'y');
}

int cfg_get_int(cfg_t *cfg, const char *name, int def)
{
    char *env_value = getenv(name);
    return env_value ? (int)strtol (env_value, NULL, 10) : def;
}
