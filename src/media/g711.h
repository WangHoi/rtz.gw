#pragma once

#include <stdint.h>

enum {
    TP_ALAW,	//G711A
    TP_ULAW		//G711U
};

unsigned char linear2alaw(int pcm_val);	/* 2's complement (16-bit range) */
int alaw2linear(unsigned char a_val);

unsigned char linear2ulaw(int pcm_val);	/* 2's complement (16-bit range) */
int ulaw2linear(unsigned char u_val);

unsigned char alaw2ulaw(unsigned char aval);
unsigned char ulaw2alaw(unsigned char uval);

/**
 * Convert pcm_alaw/ulaw to pcm_s16le
 * @return <0 error, >0 pout_len
 */
int g711_decode(void *pout_buf, int *pout_len, const void *pin_buf, const int in_len, int type);
