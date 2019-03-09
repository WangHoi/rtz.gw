#include "nbuf.h"
#include "list.h"
#include "log.h"
#include "macro_util.h"
#include <linux/uio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

enum {
    DEFAULT_CHUNK_SIZE = 65536,
};

struct nbuf_chunk {
    void *data;
    int head;
    int tail;
    struct list_head link;
};

struct nbuf_t {
    int size;
    int chunk_count;
    int chunk_capacity;
    struct list_head chunk_list;
};

static struct nbuf_chunk *nbuf_chunk_new(nbuf_t *buf);
static void nbuf_chunk_del(nbuf_t *buf, struct nbuf_chunk *c);
static struct nbuf_chunk *get_last_chunk(nbuf_t *buf);

nbuf_t *nbuf_new()
{
    return nbuf_new1(DEFAULT_CHUNK_SIZE);
}

nbuf_t *nbuf_new1(int cc)
{
    nbuf_t *buf = malloc(sizeof(nbuf_t));
    memset(buf, 0, sizeof(nbuf_t));
    INIT_LIST_HEAD(&buf->chunk_list);
    buf->chunk_capacity = cc;
    return buf;
}

void nbuf_del(nbuf_t *buf)
{
    struct nbuf_chunk *c, *tmp;
    list_for_each_entry_safe(c, tmp, &buf->chunk_list, link) {
        nbuf_chunk_del(buf, c);
    }
    free(buf);
}

int nbuf_remove(nbuf_t *buf, void *data_, int size)
{
    char *data = data_;
    int n = 0;
    struct nbuf_chunk *c, *tmp;
    list_for_each_entry_safe(c, tmp, &buf->chunk_list, link) {
        int space = MIN(size, c->tail - c->head);

        memcpy(data, c->data + c->head, space);
        data += space;
        n += space;

        size -= space;
        c->head += space;
        buf->size -= space;
        if (c->head == c->tail)
            nbuf_chunk_del(buf, c);
        if (size == 0)
            break;
    }
    return n;
}

char nbuf_removec(nbuf_t *buf)
{
    if (buf->size == 0)
        return 0;
    struct nbuf_chunk *c;
    c = list_entry(buf->chunk_list.next, struct nbuf_chunk, link);
    char ret = ((char*)c->data)[c->head++];
    --buf->size;
    if (c->head == c->tail)
        nbuf_chunk_del(buf, c);
    return ret;
}

void nbuf_consume(nbuf_t *buf, int size)
{
    struct nbuf_chunk *c, *tmp;
    list_for_each_entry_safe(c, tmp, &buf->chunk_list, link) {
        int space = MIN(size, c->tail - c->head);

        size -= space;
        c->head += space;
        buf->size -= space;
        if (c->head == c->tail)
            nbuf_chunk_del(buf, c);
        if (size == 0)
            break;
    }
}

void nbuf_append(nbuf_t *buf, const void *data_, int size)
{
    const char *data = data_;
    struct nbuf_chunk *c = get_last_chunk(buf);
    int space;
    while (c && c->tail < buf->chunk_capacity) {
        space = MIN(size, buf->chunk_capacity - c->tail);
        memcpy(c->data + c->tail, data, space);
        c->tail += space;
        buf->size += space;
        data += space;
        size -= space;

        if (c->link.next != &buf->chunk_list)
            c = list_entry(c->link.next, struct nbuf_chunk, link);
        else
            c = NULL;
    }
    while (size > 0) {
        c = nbuf_chunk_new(buf);
        c->tail = space = MIN(buf->chunk_capacity, size);
        buf->size += space;
        memcpy(c->data, data, space);
        data += space;
        size -= space;
    }
}

int nbuf_size(nbuf_t *buf)
{
    return buf->size;
}

int nbuf_empty(nbuf_t *buf)
{
    return (buf->size == 0);
}

int nbuf_peek(nbuf_t *buf, void *data_, int size)
{
    char *data = data_;
    int n = 0;
    struct nbuf_chunk *c;
    list_for_each_entry(c, &buf->chunk_list, link) {
        int space = MIN(size, c->tail - c->head);

        memcpy(data, c->data + c->head, space);
        data += space;
        n += space;

        size -= space;
        if (size == 0)
            break;
    }
    return n;
}

char nbuf_peekc(nbuf_t *buf)
{
    if (buf->size == 0)
        return 0;
    struct nbuf_chunk *c;
    c = list_entry(buf->chunk_list.next, struct nbuf_chunk, link);
    assert(c->head < c->tail);
    return ((char*)c->data)[c->head];
}

int nbuf_peekv(nbuf_t *buf, struct iovec *iov, int iov_cnt, int *psize)
{
    int i = 0;
    int size = 0;
    struct list_head *link = &buf->chunk_list;
    struct nbuf_chunk *c;
    while (i < iov_cnt && i < buf->chunk_count) {
        c = list_entry(link->next, struct nbuf_chunk, link);
        iov[i].iov_base = c->data + c->head;
        iov[i].iov_len = c->tail - c->head;
        size += c->tail - c->head;
        link = link->next;
        ++i;
    }
    if (psize)
        *psize = size;
    return i;
}

int nbuf_reserve(nbuf_t *buf, struct iovec *iov, int *iov_cnt)
{
    if (*iov_cnt < 1)
        return 0;

    int size;
    int n = 1;
    struct nbuf_chunk *c;
    if (list_empty(&buf->chunk_list)) {
        c = nbuf_chunk_new(buf);
        iov[0].iov_base = c->data;
        iov[0].iov_len = buf->chunk_capacity;
        size = iov[0].iov_len;
    } else {
        c = list_entry(buf->chunk_list.prev, struct nbuf_chunk, link);
        if (c->tail == buf->chunk_capacity) {
            c = nbuf_chunk_new(buf);
            iov[0].iov_base = c->data;
            iov[0].iov_len = buf->chunk_capacity;
            size = iov[0].iov_len;
        } else if (c->tail == 0) {
            iov[0].iov_base = c->data;
            iov[0].iov_len = buf->chunk_capacity;
            size = iov[0].iov_len;
        } else {
            iov[0].iov_base = c->data + c->head;
            iov[0].iov_len = buf->chunk_capacity - c->head;
            size = iov[0].iov_len;
            if (*iov_cnt >= 2) {
                ++n;
                c = nbuf_chunk_new(buf);
                iov[1].iov_base = c->data;
                iov[1].iov_len = buf->chunk_capacity;
                size += iov[1].iov_len;
            }
        }
    }
    *iov_cnt = n;
    return size;
}

void nbuf_commit(nbuf_t *buf, int size)
{
    struct nbuf_chunk *c = get_last_chunk(buf);
    if (!c)
        return;
    while (size > 0) {
        int space = MIN(buf->chunk_capacity - c->tail, size);
        c->tail += space;
        size -= space;
        buf->size += space;
        if (c->link.next == &buf->chunk_list)
            break;
        c = list_entry(c->link.next, struct nbuf_chunk, link);
    }
}

struct nbuf_chunk *nbuf_chunk_new(nbuf_t *buf)
{
    struct nbuf_chunk *c = malloc(sizeof(struct nbuf_chunk));
    c->data = malloc(buf->chunk_capacity);
    c->head = c->tail = 0;
    ++buf->chunk_count;
    list_add_tail(&c->link, &buf->chunk_list);
    return c;
}

void nbuf_chunk_del(nbuf_t *buf, struct nbuf_chunk *c)
{
    --buf->chunk_count;
    free(c->data);
    list_del(&c->link);
    free(c);
}

struct nbuf_chunk *get_last_chunk(nbuf_t *buf)
{
    if (list_empty(&buf->chunk_list))
        return NULL;
    struct nbuf_chunk *c, *prev;
    c = list_entry(buf->chunk_list.prev, struct nbuf_chunk, link);
    if (c->tail > 0)
        return c;
    if (c->link.prev != &buf->chunk_list) {
        prev = list_entry(c->link.prev, struct nbuf_chunk, link);
        if (prev->tail < buf->chunk_capacity)
            c = prev;
    }
    return c;
}
