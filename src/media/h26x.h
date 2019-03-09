#pragma once
#include <stddef.h>
#include <stdint.h>

enum {
    H264_NALU_SEI = 6,
    H264_NALU_SPS = 7,
    H264_NALU_PPS = 8,
    H264_NALU_IFRAME = 5,
    H264_NALU_PFRAME = 1,
    H264_NALU_STAPA = 24,
    H264_NALU_FRAGA = 28,
};

enum {
    H265_NALU_VPS_NUT = 32,
    H265_NALU_SPS_NUT = 33,
    H265_NALU_PPS_NUT = 34,
    H265_NALU_IDR_W_DLP = 19,
    H265_NALU_TRAIL_R = 1,
    H265_NALU_PREFIX_SEI_NUT = 39,
    H265_NALU_FRAG = 49,
};

#pragma pack(push, 1)
typedef struct h264_nalu_header_t {
    //byte 0
    uint8_t type : 5;
    uint8_t nri : 2;
    uint8_t f : 1;
} h264_nalu_header_t; /* 1 BYTES */
_Static_assert(sizeof(h264_nalu_header_t) == 1, "invalid sizeof(h264_nalu_header_t)");


typedef struct h264_fu_header_t {
    //byte 0
    uint8_t type : 5;
    uint8_t r : 1;
    uint8_t e : 1;
    uint8_t s : 1;
} h264_fu_header_t; /**//* 1 BYTES */
_Static_assert(sizeof(h264_fu_header_t) == 1, "invalid sizeof(h264_fu_header_t)");

typedef struct h264_fu_indicator_t {
    //byte 0
    uint8_t type : 5;
    uint8_t nri : 2;
    uint8_t f : 1;
} h264_fu_indicator_t; /* 1 BYTES */
_Static_assert(sizeof(h264_fu_indicator_t) == 1, "invalid sizeof(h264_fu_indicator_t)");

typedef struct h265_nalu_header_t {
    uint16_t layer_hi : 1;
    uint16_t type : 6;
    uint16_t f : 1;      // == 0
    uint16_t tid : 3;   // == 1
    uint16_t layer_low : 5; // == 0
} h265_nalu_header_t; /* 2 BYTES */
_Static_assert(sizeof(h265_nalu_header_t) == 2, "invalid sizeof(h265_nalu_header_t)");

typedef struct h265_fu_header_t {
    //byte 0
    uint8_t type : 6;
    uint8_t e : 1;
    uint8_t s : 1;
} h265_fu_header_t; /**//* 1 BYTES */
_Static_assert(sizeof(h265_fu_header_t) == 1, "invalid sizeof(h265_fu_header_t)");

#pragma pack(pop)

typedef struct nalu_part_t {
    const char *data;
    size_t size;
} nalu_part_t;

typedef struct sbuf_t sbuf_t;

int extract_h26x_nalus(const char *data, size_t size, nalu_part_t *units, int max_units);
sbuf_t *make_h264_decoder_config_record(const char *sps_data, size_t sps_size,
                                        const char *pps_data, size_t pps_size);
int update_h264_decoder_config_record(sbuf_t *config, const char *sps_data, size_t sps_size,
                                      const char *pps_data, size_t pps_size);
