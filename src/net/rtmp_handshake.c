#include "rtmp_handshake.h"
#include "rtmp_types.h"
#include "log.h"
#include "pack_util.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bn.h>

enum rtmp_hs_flag {
    RTMP_HS_SCHEMA0 = 1,
    RTMP_HS_SCHEMA1 = 2,
    RTMP_HS_S1_GEN = 4,
    RTMP_HS_S2_GEN = 8,
};

static const char* RFC2409_PRIME_1024 =
"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
"FFFFFFFFFFFFFFFF";

static const uint8_t FMS_KEY[] = {
    0x47, 0x65, 0x6e, 0x75, 0x69, 0x6e, 0x65, 0x20,
    0x41, 0x64, 0x6f, 0x62, 0x65, 0x20, 0x46, 0x6c,
    0x61, 0x73, 0x68, 0x20, 0x4d, 0x65, 0x64, 0x69,
    0x61, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
    0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Media Server 001
    0xf0, 0xee, 0xc2, 0x4a, 0x80, 0x68, 0xbe, 0xe8,
    0x2e, 0x00, 0xd0, 0xd1, 0x02, 0x9e, 0x7e, 0x57,
    0x6e, 0xec, 0x5d, 0x2d, 0x29, 0x80, 0x6f, 0xab,
    0x93, 0xb8, 0xe6, 0x36, 0xcf, 0xeb, 0x31, 0xae
}; // 68bytes
_Static_assert(sizeof(FMS_KEY) == 68, "invalid sizeof(FMS_KEY)");

static const uint8_t FP_KEY[62] = {
    0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20,
    0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x46, 0x6C,
    0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
    0x65, 0x72, 0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Player 001
    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
    0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
    0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
}; // 62bytes
_Static_assert(sizeof(FP_KEY) == 62, "invalid sizeof(FP_KEY)");

static const size_t HANDSHAKE_PKT_SIZE = 1536;
static const size_t KEY_DIGEST_BLOCK_SIZE = 764;
static const size_t KEY_SIZE = 128;
static const size_t DIGEST_SIZE = 32;
static const size_t C1_FP_KEY_SIZE = 30;
static const size_t C2_FP_KEY_SIZE = 62;
static const size_t S1_FMS_KEY_SIZE = 36;
static const size_t S2_FMS_KEY_SIZE = 68;

struct rtmp_hs_t {
    int flag;
    const uint8_t *c1_key;
    const uint8_t *c1_digest;
    uint8_t c1[RTMP_HANDSHAKE_C1_SIZE];
    uint8_t c2[RTMP_HANDSHAKE_C2_SIZE];
    uint8_t s1[RTMP_HANDSHAKE_S1_SIZE];
    uint8_t s2[RTMP_HANDSHAKE_S2_SIZE];
};

rtmp_hs_t *rtmp_hs_new()
{
    rtmp_hs_t *hs = malloc(sizeof(rtmp_hs_t));
    memset(hs, 0, sizeof(rtmp_hs_t));
    return hs;
}
void rtmp_hs_del(rtmp_hs_t *hs)
{
    free(hs);
}

static size_t ReadBlockOffset(const uint8_t* p, size_t payload_size)
{
    size_t size = KEY_DIGEST_BLOCK_SIZE - payload_size - 4;
    return (p[0] + p[1] + p[2] + p[3]) % size;
}

static uint8_t* hmac_sha256(const void* key, size_t keylen,
                            const void* data, size_t datalen,
                            void* result, unsigned result_len)
{
    return HMAC(EVP_sha256(), key, (int)keylen, (const uint8_t*)data, datalen, (uint8_t*)result, &result_len);
}

static int IsValidC1S1(const uint8_t* p, const uint8_t* key, size_t key_size, const uint8_t* digest)
{
    uint8_t data[HANDSHAKE_PKT_SIZE];
    size_t before_size = digest - p;
    size_t after_size = p + HANDSHAKE_PKT_SIZE - (digest + DIGEST_SIZE);
    memcpy (data, p, before_size);
    memcpy (data + before_size, digest + DIGEST_SIZE, after_size);
    uint8_t compute_digest[DIGEST_SIZE];
    hmac_sha256 (key, key_size, data, HANDSHAKE_PKT_SIZE - DIGEST_SIZE, compute_digest, (unsigned)DIGEST_SIZE);
    return (memcmp (digest, compute_digest, DIGEST_SIZE) == 0);
}

void rtmp_hs_set_c1(rtmp_hs_t *hs, const void *data)
{
    memcpy(hs->c1, data, RTMP_HANDSHAKE_C1_SIZE);
    hs->flag &= ~RTMP_HS_S1_GEN;
    hs->flag &= ~RTMP_HS_S2_GEN;

    hs->flag &= ~(RTMP_HS_SCHEMA0 | RTMP_HS_SCHEMA1);
    hs->c1_key = hs->c1_digest = NULL;
    const uint8_t *p = hs->c1;
    uint32_t time = unpack_be32 (p);
    uint32_t version = unpack_be32 (p + 4);
    p += 8;

    size_t key_offset, digest_offset;
    // try schema0: key digest
    key_offset = ReadBlockOffset(p + KEY_DIGEST_BLOCK_SIZE - 4, KEY_SIZE);
    digest_offset = ReadBlockOffset(p + KEY_DIGEST_BLOCK_SIZE, DIGEST_SIZE);
    const uint8_t *vk = FP_KEY;
    size_t vk_size = C1_FP_KEY_SIZE;
    if (IsValidC1S1(p - 8, vk, vk_size, p + KEY_DIGEST_BLOCK_SIZE + 4 + digest_offset)) {
        hs->flag |= RTMP_HS_SCHEMA0;
        hs->c1_key = p + key_offset;
        hs->c1_digest = p + KEY_DIGEST_BLOCK_SIZE + 4 + digest_offset;
        //LLOG(LL_TRACE, "C1: schema0");
    } else {
        // try schema1: digest key
        key_offset = ReadBlockOffset (p + 2 * KEY_DIGEST_BLOCK_SIZE - 4, KEY_SIZE);
        digest_offset = ReadBlockOffset (p, DIGEST_SIZE);
        if (IsValidC1S1(p - 8, vk, vk_size, p + 4 + digest_offset)) {
            hs->flag |= RTMP_HS_SCHEMA1;
            hs->c1_key = p + KEY_DIGEST_BLOCK_SIZE + key_offset;
            hs->c1_digest = p + 4 + digest_offset;
            //LLOG(LL_TRACE, "C1: schema1");
        } else {
            hs->c1_key = hs->c1_digest = NULL;
            //LLOG(LL_TRACE, "C1: invalid schema");
        }
    }
    /*
    if (hs->c1_key && hs->c1_digest) {
        LLOG(LL_TRACE, "key=%02hhx%02hhx%02hhx%02hhx digest=%02hhx%02hhx%02hhx%02hhx",
             hs->c1_key[0], hs->c1_key[1], hs->c1_key[2], hs->c1_key[3],
             hs->c1_digest[0], hs->c1_digest[1], hs->c1_digest[2], hs->c1_digest[3]);
    }
    */
}
const void *rtmp_hs_generate_s1(rtmp_hs_t *hs)
{
    if (hs->flag & RTMP_HS_S1_GEN)
        return hs->s1;
    uint8_t *p = hs->s1;
    p += pack_be32(p, (uint32_t)time(NULL));
    p += pack_be32(p, 0x01000504); /* Version */
    uint8_t pkt[HANDSHAKE_PKT_SIZE];
    memset(pkt, 0, sizeof(pkt));
    if (hs->flag & RTMP_HS_SCHEMA0) {
        memcpy(pkt, hs->s1, 8 + KEY_DIGEST_BLOCK_SIZE + KEY_DIGEST_BLOCK_SIZE - DIGEST_SIZE);
        hmac_sha256(FMS_KEY, S1_FMS_KEY_SIZE, pkt, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                    p + KEY_DIGEST_BLOCK_SIZE + 4, DIGEST_SIZE);
    } else if (hs->flag & RTMP_HS_SCHEMA1) {
        memcpy(pkt, p - 8, 8);
        memcpy(pkt + 8 + KEY_DIGEST_BLOCK_SIZE - DIGEST_SIZE, p + KEY_DIGEST_BLOCK_SIZE, KEY_SIZE);
        hmac_sha256(FMS_KEY, S1_FMS_KEY_SIZE, pkt, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                    p + 4, DIGEST_SIZE);
    } else {
        memset (p, 0, 2 * KEY_DIGEST_BLOCK_SIZE);
    }
    hs->flag |= RTMP_HS_S1_GEN;
    return hs->s1;
}
const void *rtmp_hs_generate_s2(rtmp_hs_t *hs)
{
    if (hs->flag & RTMP_HS_S2_GEN)
        return hs->s2;

    if (!hs->c1_digest) {
        memcpy(hs->s2, hs->c1, sizeof(hs->s2));
    } else {
        uint8_t temp_key[DIGEST_SIZE];
        hmac_sha256(FMS_KEY, S2_FMS_KEY_SIZE, hs->c1_digest, DIGEST_SIZE,
                    temp_key, DIGEST_SIZE);
        hmac_sha256(temp_key, DIGEST_SIZE, hs->s2, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                    &hs->s2[HANDSHAKE_PKT_SIZE - DIGEST_SIZE], DIGEST_SIZE);
    }
    hs->flag |= RTMP_HS_S2_GEN;
    return hs->s2;
}


