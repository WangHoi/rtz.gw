#pragma once
#include "wav.h"
#include "aac.h"

typedef struct sbuf_t sbuf_t;

typedef enum video_codec_type_t {
    INVALID_VIDEO_CODEC = -1,
    VIDEO_CODEC_H264,
    VIDEO_CODEC_H265,
    NUM_VIDEO_CODEC_TYPES,
} video_codec_type_t;

typedef enum audio_codec_type_t {
    INVALID_AUDIO_CODEC = -1,
    AUDIO_CODEC_PCM,
    AUDIO_CODEC_PCMA,
    AUDIO_CODEC_PCMU,
    AUDIO_CODEC_ADPCM,
    AUDIO_CODEC_AAC,
    NUM_AUDIO_CODEC_TYPES,
} audio_codec_type_t;

typedef struct video_codec_t {
    video_codec_type_t type;
    int frame_rate;
    int time_base;
    int width;
    int height;
    sbuf_t *vps_data;
    sbuf_t *sps_data;
    sbuf_t *pps_data;

    //struct HEVCConfig
    //{
    //    uint8_t   general_profile_idc;
    //    uint8_t   general_tier_flag;
    //    uint8_t   general_profile_space;
    //    uint32_t  general_profile_compatibility_flags;
    //    uint64_t  general_constraint_indicator_flags;
    //    uint8_t   general_level_idc;
    //    uint16_t  min_spatial_segmentation_idc;
    //    uint8_t   chroma_format;
    //    uint8_t   bit_depth_luma_minus8;
    //    uint8_t   bit_depth_chroma_minus8;
    //    uint8_t   temporal_id_nested;
    //    uint8_t   num_temporal_layers;
    //} hevc;

} video_codec_t;

typedef struct audio_codec_t {
    audio_codec_type_t type;
    int sample_rate;
    int bits_per_sample;
    int num_channels;
    aac_config_t aac_config;

    //AudioCodec ()
    //    : type (INVALID_AUDIO_CODEC), sample_rate (8000), bits_per_sample (8), num_channels (1), aac_config{}
    //{}
} audio_codec_t;

video_codec_t *video_codec_new();
void video_codec_del(video_codec_t *codec);
void video_codec_reset(video_codec_t *codec);

audio_codec_t *audio_codec_new();
void audio_codec_del(audio_codec_t *codec);
void audio_codec_reset(audio_codec_t *codec);
