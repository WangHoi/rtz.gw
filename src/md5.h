#pragma once
#include <stdint.h>

typedef struct {
	uint32_t buf[4];
	uint32_t bytes[2];
	uint32_t in[16];
} MD5_CTX;

void MD5Init(MD5_CTX *context);
void MD5Update(MD5_CTX *context, uint8_t const *buf, unsigned len);
void MD5Final(MD5_CTX *context, uint8_t digest[16]);
void MD5Transform(uint32_t buf[4], uint32_t const in[16]);
