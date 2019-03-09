#pragma once
#include <srtp2/srtp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/srtp.h>
int srtp_crypto_get_random(uint8_t *key, int len);

/* SRTP stuff (http://tools.ietf.org/html/rfc3711) */
#define SRTP_MASTER_KEY_LENGTH	16
#define SRTP_MASTER_SALT_LENGTH	14
#define SRTP_MASTER_LENGTH (SRTP_MASTER_KEY_LENGTH + SRTP_MASTER_SALT_LENGTH)
/* AES-GCM stuff (http://tools.ietf.org/html/rfc7714) */
#define SRTP_AESGCM128_MASTER_KEY_LENGTH	16
#define SRTP_AESGCM128_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM128_MASTER_LENGTH (SRTP_AESGCM128_MASTER_KEY_LENGTH + SRTP_AESGCM128_MASTER_SALT_LENGTH)
#define SRTP_AESGCM256_MASTER_KEY_LENGTH	32
#define SRTP_AESGCM256_MASTER_SALT_LENGTH	12
#define SRTP_AESGCM256_MASTER_LENGTH (SRTP_AESGCM256_MASTER_KEY_LENGTH + SRTP_AESGCM256_MASTER_SALT_LENGTH)

/* SRTP profiles */
typedef enum rtp_profile {
	RTZ_SRTP_AES128_CM_SHA1_32 = 1,
    RTZ_SRTP_AES128_CM_SHA1_80,
    RTZ_SRTP_AEAD_AES_128_GCM,
    RTZ_SRTP_AEAD_AES_256_GCM
} rtp_profile;

/*! \brief Helper method to get a string representation of a libsrtp error code
 * @param[in] error The libsrtp error code
 * @returns A string representation of the error code */
const char *rtz_srtp_error_str(int error);
