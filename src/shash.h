#pragma once
#include <stdint.h>

/** FNV-1a hash */
static inline uint32_t shash(const char *s)
{
    uint32_t h = 0x811c9dc5;
    uint32_t c;
    while (c = *s++) {
        h ^= c;
        h *= 0x1000193;
    }
    return h;
}
