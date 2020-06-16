#pragma once
#include <stdint.h>

struct mpsc_msg {
	volatile uint32_t id;
	union __attribute__((packed)) {
		uint8_t u8[60];
		uint16_t u16[30];
		uint32_t u32[15];
		uint64_t u64[7];
	};
};

struct mpsc_queue;
struct mpsc_queue *mpsc_queue_new(unsigned size_order);
void mpsc_queue_del(struct mpsc_queue *q);
struct mpsc_msg *mpsc_reserve(struct mpsc_queue *q);
void mpsc_commit(struct mpsc_msg *msg, uint32_t id);
struct mpsc_msg *mpsc_peek(struct mpsc_queue *q);
void mpsc_consume(struct mpsc_queue *q, struct mpsc_msg *msg);

