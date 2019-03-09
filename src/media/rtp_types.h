#pragma once
#include <stddef.h>
#include <stdint.h>

#pragma pack(push, 1)
typedef struct rtp_header_ext_t {
    uint16_t profile;
    uint16_t length_words_minus1;
} rtp_header_ext_t;

typedef struct rtp_header_t {
    uint16_t cc : 4;
    uint16_t extension : 1;
    uint16_t padding : 1;
    uint16_t version : 2; // 2
    uint16_t payload : 7;
    uint16_t marker : 1;
    uint16_t seqnum;
    uint32_t timestamp;
    uint32_t ssrc;
    rtp_header_ext_t xhdr[];
} rtp_header_t;
_Static_assert(sizeof(rtp_header_t) == 12, "Invalid rtp_header_t.");

// profile: 0xABAC
typedef struct rtp_header_ext_abac_t {
    uint32_t ntp_hi;
    uint32_t ntp_low;
    uint16_t mbz : 4;   // reserved
    uint16_t t : 1;
    uint16_t d : 1;
    uint16_t e : 1;
    uint16_t c : 1;
    uint16_t cseq : 8;
    uint16_t padding;
} rtp_header_ext_abac_t;
_Static_assert(sizeof(rtp_header_ext_abac_t) == 12, "Invalid rtp_header_ext_abac_t size.");

#pragma pack(pop)
