#pragma once
#include "macro_util.h"
#include <stdarg.h>

typedef struct sbuf_t {
    char *data;
    int size;
    int capacity; // at least size + 1
} sbuf_t;

sbuf_t *sbuf_new();
sbuf_t *sbuf_new1(int capacity);
sbuf_t *sbuf_newf(const char *format, ...) __attribute__((format(printf, 1, 2)));
sbuf_t *sbuf_newv(const char *format, va_list ap);
sbuf_t *sbuf_strdup(const char *str);
sbuf_t *sbuf_strndup(const char *str, int n);
sbuf_t *sbuf_strcpy(sbuf_t *s, const char *str);
sbuf_t *sbuf_strncpy(sbuf_t *s, const char *str, int n);
sbuf_t *sbuf_clone(sbuf_t *os);
void sbuf_resize(sbuf_t *s, int size);
void sbuf_del(sbuf_t *dst);
char *sbuf_tail(sbuf_t *dst);
void sbuf_reserve(sbuf_t *dst, int capacity);
void sbuf_clear(sbuf_t *dst);
void sbuf_makeroom(sbuf_t *dst, int freesize);
void sbuf_append(sbuf_t *dst, sbuf_t *src);
void sbuf_append1(sbuf_t *dst, const char *s);
void sbuf_append2(sbuf_t *dst, const char *s, int size);
void sbuf_appendf(sbuf_t *dst, const char *format, ...) __attribute__((format(printf, 2, 3)));
void sbuf_appendv(sbuf_t *dst, const char *format, va_list ap);
void sbuf_appendc(sbuf_t *dst, char c);
void sbuf_prepend(sbuf_t *dst, sbuf_t *src);
void sbuf_prepend1(sbuf_t *dst, const char *s);
void sbuf_prepend2(sbuf_t *dst, const char *s, int size);
void sbuf_prependc(sbuf_t *dst, char c);
int sbuf_empty(sbuf_t *s);
sbuf_t *sbuf_remove_head(sbuf_t *dst, int n);
sbuf_t *sbuf_remove_tail(sbuf_t *dst, int n);
sbuf_t *sbuf_remove_mid(sbuf_t *dst, int i, int n);
int sbuf_ends_with(sbuf_t *s, const char* str);
int sbuf_ends_withi(sbuf_t *s, const char* str);
void sbuf_printf(sbuf_t *s, const char *format, ...) __attribute__((format(printf, 2, 3)));
void sbuf_vprintf(sbuf_t *s, const char *format, va_list ap);

sbuf_t *sbuf_random_string(int len);
