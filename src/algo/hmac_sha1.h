/**
 * Functions to implement RFC-2104 (HMAC with SHA-1 hashes).
 * Placed into the public domain.
 */
#pragma once
#include "sha1.h"
#include <stdint.h>
#include <stddef.h>

typedef struct HMAC_SHA1_CTX {
    SHA1_CTX sha1ctx;
    uint8_t k_ipad[65];
    uint8_t k_opad[65];
} HMAC_SHA1_CTX;

void HMAC_SHA1_Init(HMAC_SHA1_CTX *ctx,
                    const uint8_t *key, size_t key_len);
void HMAC_SHA1_Update(HMAC_SHA1_CTX *ctx,
                      const uint8_t *data, size_t data_len);
void HMAC_SHA1_Final(uint8_t digest[20], HMAC_SHA1_CTX *ctx);
