#pragma once

typedef struct
{
    unsigned int size;
    unsigned int head, tail;
    void *data;
} cbuf_t;

/** Create new circular buffer.
 * @param order Size of the circular buffer when taking this as a power of 2.
 * @return pointer to new circular buffer */
cbuf_t *cbuf_new(const unsigned int order);

/** Free memory used by circular buffer
 * @param cb The circular buffer. */
void cbuf_del(cbuf_t* cb);

unsigned char *cbuf_head(const cbuf_t *cb);
unsigned char *cbuf_tail(const cbuf_t *cb);

/** Size in bytes of the circular buffer.
 * Is equal to 2 ^ order.
 *
 * @param cb The circular buffer.
 * @return size of the circular buffer in bytes */
int cbuf_size(const cbuf_t* cb);

/** Tell how much data has been written in bytes to the circular buffer.
 * @param cb The circular buffer.
 * @return number of bytes of how data has been written */
int cbuf_usedspace(const cbuf_t* cb);

/** Tell how much data we can write in bytes to the circular buffer.
 * @param cb The circular buffer.
 * @return number of bytes of how much data can be written */
int cbuf_unusedspace(const cbuf_t* cb);

/** Tell if the circular buffer is empty.
 * @param cb The circular buffer.
 * @return 1 if empty; otherwise 0 */
int cbuf_is_empty(const cbuf_t* cb);

/** Tell if the circular buffer is full.
 * @param cb The circular buffer.
 * @return 1 if full; otherwise 0 */
int cbuf_is_full(const cbuf_t* cb);
