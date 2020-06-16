#include "base64.h"
#include <stdint.h>
#include <math.h>
#include <assert.h>

static const char BASE64_SET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

size_t base64_encode(const void* ibuf, size_t ilen, char* obuf, size_t max_osize)
{
    if (!obuf)
        return ((4 * ilen / 3) + 3) & ~3;

    const uint8_t *pi = ibuf;
    char* po = obuf;
    size_t olen = 0;
    for (; pi + 2 < (const uint8_t*)ibuf + ilen; pi += 3) {
        *po++ = BASE64_SET[pi[0] >> 2];
        *po++ = BASE64_SET[(uint8_t)(pi[0] << 4) | (pi[1] >> 4)];
        *po++ = BASE64_SET[(uint8_t)(pi[1] << 2) | (pi[2] >> 6)];
        *po++ = BASE64_SET[pi[2]];
        olen += 4;
    }
    size_t remain = (const uint8_t*)ibuf + ilen - pi;
    if (remain == 1) {
        *po++ = BASE64_SET[pi[0] >> 2];
        *po++ = BASE64_SET[(uint8_t)(pi[0] << 4) | (pi[1] >> 4)];
        *po++ = '=';
        *po++ = '=';
        olen += 4;
    } else if (remain == 2) {
        *po++ = BASE64_SET[pi[0] >> 2];
        *po++ = BASE64_SET[(uint8_t)(pi[0] << 4) | (pi[1] >> 4)];
        *po++ = BASE64_SET[(uint8_t)(pi[1] << 2) | (pi[2] >> 6)];
        *po++ = '=';
        olen += 4;
    }
    assert(olen <= max_osize);
    return olen;
}
