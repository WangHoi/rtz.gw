#include "rtmp_types.h"
#include "sbuf.h"
#include "log.h"
#include "pack_util.h"
#include "macro_util.h"
#include <time.h>
#include <assert.h>

#if 0
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
}; // 68
static_assert (sizeof (FMS_KEY) == 68, "invalid sizeof(FMS_KEY)");

static const uint8_t FP_KEY[] = {
    0x47, 0x65, 0x6E, 0x75, 0x69, 0x6E, 0x65, 0x20,
    0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x46, 0x6C,
    0x61, 0x73, 0x68, 0x20, 0x50, 0x6C, 0x61, 0x79,
    0x65, 0x72, 0x20, 0x30, 0x30, 0x31, // Genuine Adobe Flash Player 001
    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8,
    0x2E, 0x00, 0xD0, 0xD1, 0x02, 0x9E, 0x7E, 0x57,
    0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB,
    0x93, 0xB8, 0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
}; // 62
static_assert (sizeof (FP_KEY) == 62, "invalid sizeof(FP_KEY)");

static const size_t HANDSHAKE_PKT_SIZE = 1536;
static const size_t KEY_DIGEST_BLOCK_SIZE = 764;
static const size_t KEY_SIZE = 128;
static const size_t DIGEST_SIZE = 32;
static const size_t C1_FP_KEY_SIZE = 30;
static const size_t C2_FP_KEY_SIZE = 62;
static const size_t S1_FMS_KEY_SIZE = 36;
static const size_t S2_FMS_KEY_SIZE = 68;

size_t DHWrapper::CopySharedKey (const void *ppkey, int32_t ppkey_size, void *skey, size_t skey_size)
{
    BIGNUM* ppk = nullptr;
    if ((ppk = BN_bin2bn ((const uint8_t*)ppkey, ppkey_size, 0)) == NULL) {
        log_error ("BN_bin2bn error");
        return 0;
    }

    int32_t key_size = DH_compute_key ((uint8_t*)skey, ppk, _dh);

    if (key_size < ppkey_size) {
        log_warn ("shared key size={}, ppk_size={}", key_size, ppkey_size);
    }

    if (key_size < 0 || key_size > skey_size) {
        return 0;
    }

    if (ppk) {
        BN_free (ppk);
    }

    return key_size;
}

DHWrapper::DHWrapper ()
{
    _dh = DH_new ();
    _dh->p = BN_new ();
    _dh->g = BN_new ();

    BN_hex2bn (&_dh->p, RFC2409_PRIME_1024);
    BN_set_word (_dh->g, 2);
    _dh->length = 1024;
    int ret = DH_generate_key (_dh);
    if (ret == 0) {
        log_error ("DH_generate_key error");
    }
    auto key_size = BN_num_bytes (_dh->pub_key);
    log_info ("pub_key size={}", key_size);
}

DHWrapper::~DHWrapper ()
{
    DH_free (_dh);
}

void RTMPHandshake::SetC1 (const void *data)
{
    auto p = (const uint8_t*)data;
    _c1.is_c1 = true;
    _c1.buf.assign (p, p + HANDSHAKE_PKT_SIZE);
    _c1.Parse ();
}

void RTMPHandshake::SetC2 (const void *data)
{
    auto p = (const uint8_t*)data;
    _c2.assign (p, p + HANDSHAKE_PKT_SIZE);
    CheckC2 ();
}

void RTMPHandshake::SetS1 (const void *data)
{
    auto p = (const uint8_t*)data;
    _s1.is_c1 = false;
    _s1.buf.assign (p, p + HANDSHAKE_PKT_SIZE);
    _s1.Parse ();
}

void RTMPHandshake::SetS2 (const void *data)
{
    auto p = (const uint8_t*)data;
    _s2.assign (p, p + HANDSHAKE_PKT_SIZE);
    CheckS2 ();
}

const uint8_t* RTMPHandshake::GetC1Key () const
{
    return _c1.key;
}

const uint8_t* RTMPHandshake::GetC1Digest () const
{
    return _c1.digest;
}

const uint8_t* RTMPHandshake::GetS1Key () const
{
    return _s1.key;
}

const uint8_t* RTMPHandshake::GetS1Digest () const
{
    return _s1.digest;
}

const uint8_t* RTMPHandshake::GenerateS1 ()
{
    if (_c1.buf.empty ()) {
        log_error ("generate s1 error: empty c1.");
        return nullptr;
    }
    if (!_s1.buf.empty ()) {
        return _s1.buf.data ();
    }
    _s1.is_c1 = false;
    _s1.schema = _c1.schema;
    _s1.time = (uint32_t)::time (nullptr);
    _s1.version = 0x01000504;
    _s1.buf.resize (HANDSHAKE_PKT_SIZE, 0);
    auto p = _s1.buf.data ();
    pack_be32 (p, _s1.time);
    pack_be32 (p + 4, _s1.version);
    p += 8;
    uint8_t pkt[HANDSHAKE_PKT_SIZE] = {};
    //DHWrapper dh;
    if (_c1.schema == INVALID_SCHEMA) {
        memset (p, 0, 2 * KEY_DIGEST_BLOCK_SIZE);
    } else if (_c1.schema == SCHEMA0) {
        //dh.CopySharedKey (_c1.key, KEY_SIZE, p, KEY_SIZE);
        memcpy (pkt, _s1.buf.data (), 8 + KEY_DIGEST_BLOCK_SIZE + KEY_DIGEST_BLOCK_SIZE - DIGEST_SIZE);
        hmac_sha256 (FMS_KEY, S1_FMS_KEY_SIZE, pkt, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                     p + KEY_DIGEST_BLOCK_SIZE + 4, DIGEST_SIZE);
        _s1.key = p;
        _s1.digest = p + KEY_DIGEST_BLOCK_SIZE + 4;
    } else if (_c1.schema == SCHEMA1) {
        //dh.CopySharedKey (_c1.key, KEY_SIZE, p + KEY_DIGEST_BLOCK_SIZE, KEY_SIZE);
        memcpy (pkt, p - 8, 8);
        memcpy (pkt + 8 + KEY_DIGEST_BLOCK_SIZE - DIGEST_SIZE, p + KEY_DIGEST_BLOCK_SIZE, KEY_SIZE);
        hmac_sha256 (FMS_KEY, S1_FMS_KEY_SIZE, pkt, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                     p + 4, DIGEST_SIZE);
        _s1.key = p + KEY_DIGEST_BLOCK_SIZE;
        _s1.digest = p + 4;
    }
    //SetS1 (_s1.buf.data ());
    return _s1.buf.data ();
}

const uint8_t* RTMPHandshake::GenerateS2 ()
{
    if (!_s2.empty ()) {
        return _s2.data ();
    }
    _s2.resize (HANDSHAKE_PKT_SIZE, 0);

    if (_c1.digest == nullptr) {
        _s2 = _c1.buf;
        return _s2.data ();
    }

    uint8_t temp_key[DIGEST_SIZE];
    hmac_sha256 (FMS_KEY, S2_FMS_KEY_SIZE, _c1.digest, DIGEST_SIZE,
                 temp_key, DIGEST_SIZE);
    hmac_sha256 (temp_key, DIGEST_SIZE, _s2.data(), HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                 &_s2[HANDSHAKE_PKT_SIZE - DIGEST_SIZE], DIGEST_SIZE);
    return _s2.data ();
}

void RTMPHandshake::CheckC2 ()
{
    auto p = _c2.data ();
    uint8_t tmp_key[DIGEST_SIZE];
    uint8_t compute_digest[DIGEST_SIZE];
    hmac_sha256 (FP_KEY, C2_FP_KEY_SIZE, _s1.digest, DIGEST_SIZE, tmp_key, DIGEST_SIZE);
    hmac_sha256 (tmp_key, DIGEST_SIZE, p, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                 compute_digest, DIGEST_SIZE);
    bool ok = (memcmp (compute_digest, p + HANDSHAKE_PKT_SIZE - DIGEST_SIZE, DIGEST_SIZE) == 0);
    log_info ("c2 check result {}", ok);
}

void RTMPHandshake::CheckS2 ()
{
    auto p = _s2.data ();
    uint8_t tmp_key[DIGEST_SIZE];
    uint8_t compute_digest[DIGEST_SIZE];
    hmac_sha256 (FMS_KEY, S2_FMS_KEY_SIZE, _c1.digest, DIGEST_SIZE, tmp_key, DIGEST_SIZE);
    hmac_sha256 (tmp_key, DIGEST_SIZE, p, HANDSHAKE_PKT_SIZE - DIGEST_SIZE,
                 compute_digest, DIGEST_SIZE);
    bool ok = (memcmp (compute_digest, p + HANDSHAKE_PKT_SIZE - DIGEST_SIZE, DIGEST_SIZE) == 0);
    log_info ("s2 check result {}", ok);
}

size_t RTMPHandshake::ReadBlockOffset (const uint8_t* p, size_t payload_size)
{
    auto size = KEY_DIGEST_BLOCK_SIZE - payload_size - 4;
    return (p[0] + p[1] + p[2] + p[3]) % size;
}

bool RTMPHandshake::IsValidC1S1 (const uint8_t* p, const uint8_t* key, size_t key_size, const uint8_t* digest)
{
    uint8_t data[HANDSHAKE_PKT_SIZE];
    auto before_size = digest - p;
    auto after_size = p + HANDSHAKE_PKT_SIZE - (digest + DIGEST_SIZE);
    memcpy (data, p, before_size);
    memcpy (data + before_size, digest + DIGEST_SIZE, after_size);
    uint8_t compute_digest[DIGEST_SIZE];
    hmac_sha256 (key, key_size, data, HANDSHAKE_PKT_SIZE - DIGEST_SIZE, compute_digest, DIGEST_SIZE);
    return (memcmp (digest, compute_digest, DIGEST_SIZE) == 0);
}

bool RTMPHandshake::IsValidC2 (const uint8_t* p, const uint8_t* key, const uint8_t* digest)
{
    return false;
}

bool RTMPHandshake::IsValidS2 (const uint8_t* p, const uint8_t* key, const uint8_t* digest)
{
    return false;
}

void RTMPHandshake::C1S1::Parse ()
{
    assert (!buf.empty ());
    auto p = buf.data ();
    time = unpack_be32 (p);
    version = unpack_be32 (p + 4);
    p += 8;

    size_t key_offset, digest_offset;
    // try schema0: key digest
    key_offset = ReadBlockOffset (p + KEY_DIGEST_BLOCK_SIZE - 4, KEY_SIZE);
    digest_offset = ReadBlockOffset (p + KEY_DIGEST_BLOCK_SIZE, DIGEST_SIZE);
    auto vk = is_c1 ? FP_KEY : FMS_KEY;
    auto vk_size = is_c1 ? C1_FP_KEY_SIZE : S1_FMS_KEY_SIZE;
    if (IsValidC1S1 (p - 8, vk, vk_size, p + KEY_DIGEST_BLOCK_SIZE + 4 + digest_offset)) {
        schema = SCHEMA0;
        key = p + key_offset;
        digest = p + KEY_DIGEST_BLOCK_SIZE + 4 + digest_offset;
        log_info ("{}: schema0", is_c1 ? "c1" : "s1");
    } else {
        // try schema1: digest key
        key_offset = ReadBlockOffset (p + 2 * KEY_DIGEST_BLOCK_SIZE - 4, KEY_SIZE);
        digest_offset = ReadBlockOffset (p, DIGEST_SIZE);
        if (IsValidC1S1 (p - 8, vk, vk_size, p + 4 + digest_offset)) {
            schema = SCHEMA1;
            key = p + KEY_DIGEST_BLOCK_SIZE + key_offset;
            digest = p + 4 + digest_offset;
            log_info ("{}: schema1", is_c1 ? "c1" : "s1");
        } else {
            schema = INVALID_SCHEMA;
            key = digest = nullptr;
            log_info ("{}: invalid schema", is_c1 ? "c1" : "s1");
        }
    }
    log_info ("key={:02x}{:02x}{:02x}{:02x} digest={:02x}{:02x}{:02x}{:02x}",
              key[0], key[1], key[2], key[3],
              digest[0], digest[1], digest[2], digest[3]);
}
#endif

size_t amf0_read_fieldname(const void *data, size_t size, sbuf_t *s)
{
    if (size <= 2) {
        sbuf_clear(s);
        return size;
    }
    uint16_t str_size = MIN(size - 2, unpack_be16(data));
    sbuf_strncpy(s, data + 2, str_size);
    return 2 + str_size;
}

size_t amf0_read_string(const void *data, size_t size, sbuf_t *s)
{
    if (size <= 3) {
        sbuf_clear(s);
        return size;
    }
    const char *p = data;
    assert(p[0] == AMF0_TYPE_STRING);
    uint16_t str_size = MIN(size - 3, unpack_be16(p + 1));
    sbuf_strncpy(s, p + 3, str_size);
    return 3 + str_size;
}

size_t amf0_read_number(const void *data, size_t size, double *n)
{
    if (size < 9) {
        *n = 0;
        return size;
    }
    const char *p = data;
    assert (p[0] == AMF0_TYPE_NUMBER);
    ++p;
    uint8_t *q = (uint8_t*)n;
    q[0] = p[7];
    q[1] = p[6];
    q[2] = p[5];
    q[3] = p[4];
    q[4] = p[3];
    q[5] = p[2];
    q[6] = p[1];
    q[7] = p[0];
    return 9;
}

size_t amf0_read_boolean(const void *data, size_t size, int *b)
{
    if (size < 2) {
        *b = 0;
        return size;
    }
    const char *p = data;
    assert(p[0] == AMF0_TYPE_BOOLEAN);
    *b = p[1];
    return 2;
}

size_t amf0_skip(const void *data, size_t size)
{
    const uint8_t *p = data;
    if (p[0] == AMF0_TYPE_NUMBER) {
        return 9;
    } else if (p[0] == AMF0_TYPE_OBJECT_END_MARKER) {
        return 1;
    } else if (p[0] == AMF0_TYPE_BOOLEAN) {
        return 2;
    } else if (p[0] == AMF0_TYPE_NULL) {
        return 1;
    } else if (p[0] == AMF0_TYPE_STRING) {
        sbuf_t *str = sbuf_new();
        size_t n = amf0_read_string(p, size, str);
        sbuf_del(str);
        return n;
    } else if (p[0] == AMF0_TYPE_OBJECT) {
        ++p;
        --size;
        sbuf_t *str = sbuf_new();
        while (size >= 3) {
            size_t n = amf0_read_fieldname(p, size, str);
            p += n;
            size -= n;
            if (p[0] == AMF0_TYPE_OBJECT_END_MARKER) {
                ++p;
                --size;
                break;
            }
            n = amf0_skip(p, size);
            p += n;
            size -= n;
        }
        sbuf_del(str);
        return (p - (const uint8_t*)data);
    } else {
        LLOG(LL_ERROR, "unhandled AMF type %hhu", p[0]);
        return 0;
    }
}

size_t amf0_write_string(void *data, size_t size, const char *str)
{
    if (size < 3) return 0;

    uint8_t *p = data;
    *p++ = AMF0_TYPE_STRING;

    size -= 2;
    int len = strlen(str);
    if ((int)size > len)
        size = len;
    pack_be16(p, (uint16_t)size);
    memcpy (p + 2, str, size);
    return size + 3;
}

size_t amf0_write_boolean(void *data, size_t size, int b)
{
    if (size < 2) return 0;

    uint8_t *p = data;
    *p++ = AMF0_TYPE_BOOLEAN;
    *p++ = (b ? 1 : 0);
    return 2;
}

size_t amf0_write_field_name(void *data, size_t size, const char *str)
{
    if (size < 2) return 0;

    uint8_t *p = data;
    size -= 2;
    int len = strlen(str);
    if ((int)size > len)
        size = len;
    pack_be16(p, (uint16_t)size);
    memcpy (p + 2, str, size);
    return size + 2;
}

size_t amf0_write_number(void *data, size_t size, double number)
{
    if (size < 9) return 0;

    const uint8_t *q = (const uint8_t*)&number;
    uint8_t *p = data;
    *p++ = AMF0_TYPE_NUMBER;
    p[0] = q[7];
    p[1] = q[6];
    p[2] = q[5];
    p[3] = q[4];
    p[4] = q[3];
    p[5] = q[2];
    p[6] = q[1];
    p[7] = q[0];
    return 9;
}

size_t amf0_write_null(void *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t *p = data;
    p[0] = AMF0_TYPE_NULL;
    return 1;
}

size_t amf0_write_object_start(void *data, size_t size)
{
    if (size < 1) return 0;

    uint8_t *p = data;
    p[0] = AMF0_TYPE_OBJECT;
    return 1;
}

size_t amf0_write_object_end(void *data, size_t size)
{
    if (size < 3) return 0;

    uint8_t* p = data;
    *p++ = 0;
    *p++ = 0;
    *p++ = AMF0_TYPE_OBJECT_END_MARKER;
    return 3;
}

unsigned char rtmp_chunk_header_fmt(unsigned char hdr0)
{
    return (hdr0 & 0xc0) >> 6;
}

unsigned char rtmp_chunk_header_len(unsigned char fmt)
{
    if (fmt == 0)
        return RTMP_CHUNK_HEADER_SIZE_FMT0;
    else if (fmt == 1)
        return RTMP_CHUNK_HEADER_SIZE_FMT1;
    else if (fmt == 2)
        return RTMP_CHUNK_HEADER_SIZE_FMT2;
    else if (fmt == 3)
        return RTMP_CHUNK_HEADER_SIZE_FMT3;
    assert(0);
    return 1;
}

unsigned char rtmp_chunk_channel(unsigned char hdr0)
{
    return (hdr0 & 0x3f);
}

void rtmp_write_pong(const char *ev_data, int ev_size,
                     rtmp_write_cb write_cb, void *udata)
{
    char buf[64];
    char *p = buf;
    p += rtmp_write_header0(p, RTMP_NETWORK_CHANNEL, 0, 2 + ev_size, RTMP_MESSAGE_USER_CONTROL, 0);
    p += pack_be16(p, RTMP_EVENT_PING_RESPONSE);
    memcpy (p, ev_data, ev_size);
    p += ev_size;
    *p = 0;
    write_cb(buf, (int)(p - buf), udata);
}

int rtmp_write_header0(void* data, unsigned char chunk_channel, uint32_t timestamp,
                       uint32_t body_size, rtmp_message_type_t msg_type, uint32_t msg_stream_id)
{
    uint8_t *p = data;
    assert(chunk_channel < 64);
    *p++ = (chunk_channel & 0x3f);
    if (timestamp < 0xffffff)
        p += pack_be24(p, timestamp);
    else
        p += pack_be24(p, 0xffffff);
    p += pack_be24(p, body_size);
    *p++ = msg_type;
    pack_le32(p, msg_stream_id);
    if (timestamp < 0xffffff) {
        return 12;
    } else {
        p += pack_be32(p, timestamp);
        return 16;
    }
}

int rtmp_write_header3(void* data, unsigned char chunk_channel)
{
    uint8_t *p = data;
    assert(chunk_channel < 64);
    *p++ = 0xc0 | (chunk_channel & 0x3f);
    return 1;
}

void rtmp_write_chunk(unsigned channel, uint32_t timestamp,
                      rtmp_message_type_t type, uint32_t msg_stream_id,
                      const void *data, int data_size,
                      rtmp_write_cb write_cb, void *udata)
{
    // split message to chunks
    const char *p = data;
    int first = 1;
    int size = data_size;
    while (size > 0) {
        int n = size;
        if (n > RTMP_DEFAULT_CHUNK_BODY_SIZE)
            n = RTMP_DEFAULT_CHUNK_BODY_SIZE;
        char buf[RTMP_MAX_CHUNK_HEADER_SIZE];
        int m;
        if (first) {
            m = rtmp_write_header0(buf, channel, timestamp, data_size,
                                   type, msg_stream_id);
            first = 0;
        } else {
            m = rtmp_write_header3(buf, channel);
        }
        write_cb(buf, m, udata);
        write_cb(p, n, udata);
        p += n;
        size -= n;
    }
}
