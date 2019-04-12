#pragma once
struct iovec;
typedef struct nbuf_t nbuf_t;

nbuf_t *nbuf_new();
nbuf_t *nbuf_new1(int chunk_capacity);
void nbuf_del(nbuf_t *buf);
int nbuf_remove(nbuf_t *buf, void *data, int size);
char nbuf_removec(nbuf_t *buf);
void nbuf_append(nbuf_t *buf, const void *data, int size);
int nbuf_size(nbuf_t *buf);
int nbuf_empty(nbuf_t *buf);

int nbuf_peek(nbuf_t *buf, void *data, int size);
char nbuf_peekc(nbuf_t *buf);
int nbuf_peekv(nbuf_t *buf, struct iovec *iov, int iov_cnt, int *size);
void nbuf_consume(nbuf_t *buf, int size);
int nbuf_reserve(nbuf_t *buf, struct iovec *iov, int *iov_cnt);
void nbuf_commit(nbuf_t *buf, int size);

void nbuf_init_free_list_ct();
void nbuf_cleanup_free_list_ct();
