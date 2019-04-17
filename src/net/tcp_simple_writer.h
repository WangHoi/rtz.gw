#pragma once
#include "tcp_chan.h"
#include <sys/uio.h>

typedef struct tcp_simple_writer_t tcp_simple_writer_t;

tcp_simple_writer_t *tcp_simple_writer_new(tcp_chan_t *chan);
int tcp_simple_writer_perform(tcp_simple_writer_t *w, const void *data, int size);
int tcp_simple_writer_performv(tcp_simple_writer_t *w, struct iovec *iov, int iov_cnt);
void tcp_simple_writer_sent_notify(tcp_simple_writer_t *w);
int tcp_simple_writer_buf_size(tcp_simple_writer_t *w);
void tcp_simple_writer_del(tcp_simple_writer_t *w);
