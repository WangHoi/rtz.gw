#pragma once
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include <stdint.h>

//#include <openssl/dh.h>
//#include <openssl/evp.h>
//#include <openssl/hmac.h>
//#include <openssl/bn.h>

// #NOTE: RTMP Header: Message Stream ID !!!Little Endian!!!

enum {
    FLV_VIDEO_CODEC_H264 = 7,

    FLV_AUDIO_CODEC_PCMA = 7,
    FLV_AUDIO_CODEC_PCMU = 8,
    FLV_AUDIO_CODEC_AAC = 10,
};

enum FLVVideoFrame {
    FLV_VIDEO_KEY_FRAME = 1,
    FLV_VIDEO_INTER_FRAME = 2,
};

enum FLVAVCPacketType {
    FLV_AVC_SEQUENCE_HEADER = 0,
    FLV_AVC_NALU = 1,
    FLV_AVC_END_SEQUENCE = 2,
};

enum {
    RTMP_CHUNK_HEADER_SIZE_FMT0 = 12,
    RTMP_CHUNK_HEADER_SIZE_FMT1 = 8,
    RTMP_CHUNK_HEADER_SIZE_FMT2 = 4,
    RTMP_CHUNK_HEADER_SIZE_FMT3 = 1,
    RTMP_DEFAULT_CHUNK_BODY_SIZE = 128,
    RTMP_HANDSHAKE_C0 = 3,
    RTMP_HANDSHAKE_C0_SIZE = 1,
    RTMP_HANDSHAKE_C1_SIZE = 1536,
    RTMP_HANDSHAKE_C2_SIZE = 1536,
    RTMP_HANDSHAKE_S0_SIZE = 1,
    RTMP_HANDSHAKE_S1_SIZE = 1536,
    RTMP_HANDSHAKE_S2_SIZE = 1536,
    RTMP_MAX_CHUNK_STREAMS = 64,
    RTMP_MAX_CHUNK_HEADER_SIZE = 32,
};

typedef enum rtmp_channel_t {
    RTMP_NETWORK_CHANNEL = 2,   ///< channel for network-related messages (bandwidth report, ping, etc)
    RTMP_SYSTEM_CHANNEL,        ///< channel for sending server control messages
    RTMP_AUDIO_CHANNEL,         ///< channel for audio data
    RTMP_NOTIFY_CHANNEL,        ///< channel for notify
    RTMP_AV_CHANNEL = 6,		///< channel for a/v data
    RTMP_VIDEO_CHANNEL = 7,     ///< channel for video data
    RTMP_SOURCE_CHANNEL = 8,    ///< channel for a/v invokes
} rtmp_channel_t;

typedef enum rtmp_message_type_t {
    RTMP_MESSAGE_SET_CHUNK_SIZE = 0x01,     ///< chunk size change
    RTMP_MESSAGE_ABORT = 0x02,              ///< abort peer
    RTMP_MESSAGE_ACK = 0x03,                ///< number of bytes read
    RTMP_MESSAGE_USER_CONTROL = 0x04,       ///< ping
    RTMP_MESSAGE_WINDOW_ACK_SIZE = 0x05,    ///< server bandwidth
    RTMP_MESSAGE_SET_PEER_BANDWIDTH = 0x06, ///< client bandwidth
    RTMP_MESSAGE_AUDIO = 0x08,              ///< audio packet
    RTMP_MESSAGE_VIDEO = 0x09,              ///< video packet
    RTMP_MESSAGE_AMF3_CMD = 0x11,           ///< flex message
    RTMP_MESSAGE_AMF0_NOTIFY = 0x12,        ///< some notification
    RTMP_MESSAGE_AMF0_CMD = 0x14,           ///< invoke some stream action
    RTMP_MESSAGE_METADATA = 0x16,           ///< FLV metadata
} rtmp_message_type_t;

typedef enum rtmp_event_type_t {
    RTMP_EVENT_STREAM_BEGIN = 0,
    RTMP_EVENT_STREAM_EOF = 1,
    RTMP_EVENT_STREAM_DRY = 2,
    RTMP_EVENT_SET_BUFFER_LENGTH = 3,
    RTMP_EVENT_STREAM_IS_RECORDED = 4,
    RTMP_EVENT_PING_REQUEST = 6,
    RTMP_EVENT_PING_RESPONSE = 7,
} rtmp_event_type_t;

typedef struct rtmp_chunk_t {
    uint32_t timestamp;
    int32_t timestamp_delta;
    uint32_t body_size;
    uint32_t msg_stream_id;
    unsigned char ext_timestamp_present;
    unsigned char chunk_channel;
    unsigned char type_id;
} rtmp_chunk_t;

typedef enum rtmp_amf0_type_t {
    AMF0_TYPE_NUMBER = 0,
    AMF0_TYPE_BOOLEAN = 1,
    AMF0_TYPE_STRING = 2,
    AMF0_TYPE_OBJECT = 3,
    AMF0_TYPE_NULL = 5,
    AMF0_TYPE_UNDEFINED = 6,
    AMF0_TYPE_REFERENCE = 7,
    AMF0_TYPE_ECMA_ARRAY = 8,
    AMF0_TYPE_OBJECT_END_MARKER = 9,
    AMF0_TYPE_STRICT_ARRAY_MARKER = 0x0a,
    AMF0_TYPE_DATE_MARKER = 0x0b,
    AMF0_TYPE_LONG_STRING_MARKER = 0x0c,
    AMF0_TYPE_UNSUPPORTED_MARKER = 0x0d,
    AMF0_TYPE_XML_DOCUMENT_MARKER = 0x0f,
    AMF0_TYPE_TYPED_OBJECT_MARKER = 0x10,
} rtmp_amf0_type_t;

typedef struct sbuf_t sbuf_t;

typedef void (*rtmp_write_cb)(const void* data, int size, void *udata);

size_t amf0_read_fieldname(const void *data, size_t size, sbuf_t *s);
size_t amf0_read_string(const void *data, size_t size, sbuf_t *s);
size_t amf0_read_number(const void *data, size_t size, double *n);
size_t amf0_read_boolean(const void *data, size_t size, int *b);
size_t amf0_skip(const void *data, size_t size);

size_t amf0_write_string(void *data, size_t size, const char *s);
size_t amf0_write_boolean(void *data, size_t size, int b);
size_t amf0_write_field_name(void *data, size_t size, const char *s);
size_t amf0_write_number(void *data, size_t size, double number);
size_t amf0_write_null(void *data, size_t size);
size_t amf0_write_object_start(void *data, size_t size);
size_t amf0_write_object_end(void *data, size_t size);

unsigned char rtmp_chunk_header_fmt(unsigned char hdr0);
unsigned char rtmp_chunk_header_len(unsigned char fmt);
unsigned char rtmp_chunk_channel(unsigned char hdr0);

void rtmp_write_ping(const void *ev_data, int ev_size,
    rtmp_write_cb write_cb, void *udata);
void rtmp_write_pong(const void *ev_data, int ev_size,
                     rtmp_write_cb write_cb, void *udata);
int rtmp_write_header0(void* data, unsigned char chunk_channel, uint32_t timestamp,
                       uint32_t body_size, rtmp_message_type_t msg_type, uint32_t msg_stream_id);
int rtmp_write_header1(void *data, unsigned char chunk_channel, uint32_t dt,
    uint32_t body_size, rtmp_message_type_t msg_type);
int rtmp_write_header3(void* data, unsigned char chunk_channel);
void rtmp_write_chunk(unsigned channel, uint32_t timestamp,
                      rtmp_message_type_t type, uint32_t msg_stream_id,
                      const void *data, int data_size,
                      rtmp_write_cb write_cb, void *udata);

#if 0
inline unsigned char* hmac_sha256 (const void *key, size_t keylen,
                                   const void *data, size_t datalen,
                                   void *result, size_t resultlen_)
{
    auto result_len = (unsigned)resultlen_;
    return HMAC (EVP_sha256 (), key, (int)keylen, (const uint8_t*)data, datalen, (uint8_t*)result, &result_len);
}

class DHWrapper
{
public:
    /**
    * generate and copy the shared key.
    * generate the shared key with peer public key.
    * @param ppkey peer public key.
    * @param ppkey_size the size of ppkey.
    * @param skey the computed shared key.
    * @param skey_size the max shared key size, output the actual shared key size.
    *       user should never ignore this size.
    */
    size_t CopySharedKey (const void *ppkey, int32_t ppkey_size, void *skey, size_t skey_size);

    DHWrapper ();
    ~DHWrapper ();
private:
    DH* _dh;
};

class RTMPHandshake
{
public:
    enum SchemaType
    {
        INVALID_SCHEMA = -1,
        SCHEMA0, // key digest
        SCHEMA1, // digest key
    };
    void SetC1 (const void *data);
    void SetC2 (const void *data);
    void SetS1 (const void *data);
    void SetS2 (const void *data);
    const uint8_t* GetC1Key () const;
    const uint8_t* GetC1Digest () const;
    const uint8_t* GetS1Key () const;
    const uint8_t* GetS1Digest () const;
    const uint8_t* GenerateS1 ();
    const uint8_t* GenerateS2 ();

private:
    struct C1S1
    {
        bool is_c1 = false;
        std::vector<uint8_t> buf;
        SchemaType schema = INVALID_SCHEMA;
        uint32_t time = 0;
        uint32_t version = 0;
        const uint8_t* key = nullptr;
        const uint8_t* digest = nullptr;

        void Parse ();
    };
    C1S1 _c1;
    std::vector<uint8_t> _c2;
    C1S1 _s1;
    std::vector<uint8_t> _s2;

    void CheckC2 ();
    void CheckS2 ();

    // payload_size: 128 for key block, 32 for digest block
    static size_t ReadBlockOffset (const uint8_t* p, size_t payload_size);
    static bool IsValidC1S1 (const uint8_t* p, const uint8_t* key, size_t key_size, const uint8_t* digest);
    static bool IsValidC2 (const uint8_t* p, const uint8_t* key, const uint8_t* digest);
    static bool IsValidS2 (const uint8_t* p, const uint8_t* key, const uint8_t* digest);
};
#endif
