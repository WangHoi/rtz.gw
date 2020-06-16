#include "mpsc_queue.h"
#include "cbuf.h"
#include "macro_util.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

_Static_assert(sizeof(struct mpsc_msg) == 64, "Invalid sizeof(struct mpsc_msg)");

struct mpsc_queue {
	cbuf_t *buf;
};

struct mpsc_queue *mpsc_queue_new(unsigned size_order)
{
	struct mpsc_queue *q = malloc(sizeof(struct mpsc_queue));
	if (!q)
		return NULL;
	q->buf = cbuf_new(size_order);
	if (!q->buf) {
		free(q);
		return NULL;
	}
	return q;
}

void mpsc_queue_del(struct mpsc_queue *q)
{
	cbuf_del(q->buf);
	free(q);
}

struct mpsc_msg *mpsc_reserve(struct mpsc_queue *q)
{
	struct mpsc_msg *msg;
	const uint32_t write_size = 64;

	while (1) {
		// Check for potential overflow
		unsigned s = q->buf->size;
        unsigned r = ATOMIC_LOAD_RELAXED(&q->buf->head);
		unsigned w = ATOMIC_LOAD(&q->buf->tail);
		if ((w - r) > (s - write_size)) return NULL;

		// Point to the newly allocated space
		msg = (struct mpsc_msg*)cbuf_tail(q->buf);

		// Increment the write position, leaving the loop if this is the thread that succeeded
		if (ATOMIC_COMPARE_AND_SWAP(&q->buf->tail, w, w + write_size)) {
			// Safe to set payload size after thread claims ownership of this allocated range
			break;
		}
	}

	return msg;
}

void mpsc_commit(struct mpsc_msg *msg, uint32_t id)
{
	// Ensure message writes complete before commit
	WRITE_FENCE;

	// Setting the message ID signals to the consumer that the message is ready
	ATOMIC_STORE(&msg->id, id);
}

struct mpsc_msg *mpsc_peek(struct mpsc_queue *q)
{
	struct mpsc_msg *ptr;

	// First check that there are bytes queued
	if (cbuf_is_empty(q->buf)) return NULL;

	// Messages are in the queue but may not have been commit yet
	// Messages behind this one may have been commit but it's not reachable until
	// the next one in the queue is ready.
	ptr = (struct mpsc_msg*)cbuf_head(q->buf);
	if (ATOMIC_LOAD(&ptr->id))
		return ptr;

	return NULL;
}

void mpsc_consume(struct mpsc_queue *q, struct mpsc_msg *msg)
{
	// Setting the message ID to "not ready" serves as a marker to the consumer that even though
	// space has been allocated for a message, the message isn't ready to be consumed
	// yet.
	//
	// We can't do that when allocating the message because multiple threads will be fighting for
	// the same location. Instead, clear out any messages just read by the consumer before advancing
	// the read position so that a winning thread's allocation will inherit the "not ready" state.
	//
	// This costs some write bandwidth and has the potential to flush cache to other cores.
	memset (msg, 0, sizeof(struct mpsc_msg));

	// Ensure clear completes before advancing the read position
	WRITE_FENCE;
    ATOMIC_ADD_RELAXED(&q->buf->head, sizeof(struct mpsc_msg));
}

