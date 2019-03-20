#include "sbuf.h"
#include "macro_util.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <strings.h>

static inline int sbuf_roundup_capacity(int capacity)
{
    return (capacity + 15) & ~15;
}

sbuf_t *sbuf_new()
{
    return sbuf_new1(1024);
}

sbuf_t *sbuf_new1(int capacity)
{
    if (capacity < 16)
        capacity = 16;
    capacity = sbuf_roundup_capacity(capacity);
    sbuf_t *s = malloc(sizeof(sbuf_t));
    s->data = malloc(capacity);
    s->data[0] = 0;
    s->size = 0;
    s->capacity = capacity;
    return s;
}

sbuf_t *sbuf_newf(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sbuf_t *s = sbuf_newv(format, ap);
    va_end(ap);
    return s;
}

sbuf_t *sbuf_newv(const char *format, va_list ap)
{
    char *data;
    int size = vasprintf(&data, format, ap);
    if (size < 0)
        return sbuf_new();
    sbuf_t *s = malloc(sizeof(sbuf_t));
    s->data = data;
    s->size = size;
    s->capacity = size + 1;
    return s;
}

sbuf_t *sbuf_strdup(const char *str)
{
    return sbuf_strndup(str, strlen(str));
}

sbuf_t *sbuf_strndup(const char *str, int n)
{
    sbuf_t* s = sbuf_new1(n + 1);
    memcpy(s->data, str, n);
    s->data[n] = 0;
    s->size = n;
    return s;
}

sbuf_t *sbuf_strcpy(sbuf_t* s, const char *str)
{
    return sbuf_strncpy(s, str, strlen(str));
}

sbuf_t *sbuf_strncpy(sbuf_t* s, const char *str, int n)
{
    sbuf_reserve(s, n + 1);
    memcpy(s->data, str, n);
    s->data[n] = 0;
    s->size = n;
    return s;
}

sbuf_t *sbuf_clone(sbuf_t *os)
{
    sbuf_t *s = sbuf_new1(os->capacity);
    memcpy(s->data, os->data, os->size + 1);
    s->size = os->size;
    return s;
}

void sbuf_resize(sbuf_t *s, int size)
{
    sbuf_reserve(s, size + 1);
    s->size = size;
    s->data[size] = 0;
}

void sbuf_del(sbuf_t *dst)
{
    free(dst->data);
    free(dst);
}

char *sbuf_tail(sbuf_t *dst)
{
    return dst->data + dst->size;
}

void sbuf_reserve(sbuf_t *dst, int capacity)
{
    if (dst->capacity < capacity) {
        capacity = sbuf_roundup_capacity(capacity);
        dst->capacity = capacity;
        dst->data = realloc(dst->data, capacity);
    }
}

void sbuf_clear(sbuf_t *dst)
{
    dst->size = 0;
    dst->data[0] = 0;
}

void sbuf_makeroom(sbuf_t *dst, int freespace)
{
    sbuf_reserve(dst, dst->size + freespace + 1);
}

void sbuf_append(sbuf_t *dst, sbuf_t *src)
{
    sbuf_append2(dst, src->data, src->size);
}

void sbuf_append1(sbuf_t *dst, const char *s)
{
    sbuf_append2(dst, s, strlen(s));
}

void sbuf_append2(sbuf_t *dst, const char *s, int size)
{
    sbuf_reserve(dst, dst->size + size + 1);
    memcpy(dst->data + dst->size, s, size);
    dst->size += size;
    dst->data[dst->size] = 0;
}

void sbuf_appendf(sbuf_t *dst, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sbuf_appendv(dst, format, ap);
    va_end(ap);
}

void sbuf_appendv(sbuf_t *dst, const char *format, va_list ap)
{
    va_list saved;
    va_copy(saved, ap);
    int size = vsnprintf(dst->data + dst->size, dst->capacity - dst->size,
                         format, ap);
    if (size < 0) {
        va_end(saved);
        return;
    }
    if (dst->size + size >= dst->capacity) {
        sbuf_reserve(dst, dst->size + size + 1);
        va_copy(ap, saved);
        va_end(saved);
        vsnprintf(dst->data + dst->size, dst->capacity - dst->size,
                  format, ap);
    }
    dst->size += size;
}

void sbuf_appendc(sbuf_t *dst, char c)
{
    sbuf_reserve(dst, dst->size + 2);
    dst->data[dst->size++] = c;
    dst->data[dst->size] = 0;
}

void sbuf_prepend(sbuf_t *dst, sbuf_t *src)
{
    sbuf_prepend2(dst, src->data, src->size);
}

void sbuf_prepend1(sbuf_t *dst, const char *s)
{
    sbuf_prepend2(dst, s, strlen(s));
}

void sbuf_prepend2(sbuf_t *dst, const char *s, int size)
{
    sbuf_reserve(dst, dst->size + size + 1);
    memmove(dst->data + size, dst->data, dst->size);
    memcpy(dst->data, s, size);
    dst->size += size;
    dst->data[dst->size] = 0;
}

void sbuf_prependc(sbuf_t *dst, char c)
{
    sbuf_reserve(dst, dst->size + 2);
    memmove(dst->data + 1, dst->data, dst->size);
    dst->data[0] = c;
    ++dst->size;
    dst->data[dst->size] = 0;
}

int sbuf_empty(sbuf_t *s)
{
    return (s->size == 0);
}

sbuf_t *sbuf_remove_head(sbuf_t *dst, int n)
{
    if (n > dst->size)
        n = dst->size;
    memmove(dst->data, dst->data + n, dst->size - n);
    dst->size -= n;
    dst->data[dst->size] = 0;
    return dst;
}

sbuf_t *sbuf_remove_tail(sbuf_t *dst, int n)
{
    if (n > dst->size)
        n = dst->size;
    dst->size -= n;
    dst->data[dst->size] = 0;
    return dst;
}

sbuf_t *sbuf_remove_mid(sbuf_t *dst, int i, int n)
{
    if (i >= dst->size)
        return dst;
    if (i + n > dst->size)
        n = dst->size - i;
    memmove(dst->data + i, dst->data + i + n, dst->size - (i + n));
    dst->size -= n;
    dst->data[dst->size] = 0;
    return dst;
}

int sbuf_ends_with(sbuf_t *s, const char *str)
{
    int n = strlen(str);
    if (s->size < n)
        return 0;
    return strncmp(s->data + (s->size - n), str, n) == 0;
}

int sbuf_ends_withi(sbuf_t *s, const char *str)
{
    int n = strlen(str);
    if (s->size < n)
        return 0;
    return strncasecmp(s->data + (s->size - n), str, n) == 0;
}

void sbuf_printf(sbuf_t *s, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    sbuf_vprintf(s, format, ap);
    va_end(ap);
}

void sbuf_vprintf(sbuf_t *s, const char *format, va_list ap)
{
    va_list saved;
    va_copy(saved, ap);
    int size = vsnprintf(s->data, s->capacity, format, saved);
    va_end(saved);
    if (size < 0) {
        sbuf_clear(s);
    } else if (size < s->capacity) {
        s->size = size;
    } else {
        sbuf_reserve(s, size + 1);
        s->size = vsnprintf(s->data, s->capacity, format, ap);
    }
}

sbuf_t *sbuf_random_string(int len)
{
    sbuf_t *b = sbuf_new1(len + 1);
    int i;
    static const char CHARSET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static const size_t CHARSET_LEN = ARRAY_SIZE(CHARSET) - 1;
    for (i = 0; i < len; ++i)
        sbuf_appendc(b, CHARSET[rand() % CHARSET_LEN]);
    return b;
}
