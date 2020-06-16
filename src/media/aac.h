#pragma once

#include <stdint.h>

typedef enum aac_aot_t {
    AAC_MAIN = 1,
    AAC_LC = 2,
    AAC_SSR = 3,
    AAC_SBR = 5,    // HE-AAC v1
    AAC_PS = 29,    // HE-AAC v2 Profile
} aac_aot_t;

typedef enum acc_sample_freq_t {
    AAC_SAMPLE_FREQ_96000, // 0
    AAC_SAMPLE_FREQ_88200, // 1
    AAC_SAMPLE_FREQ_64000, // 2
    AAC_SAMPLE_FREQ_48000, // 3
    AAC_SAMPLE_FREQ_44100, // 4
    AAC_SAMPLE_FREQ_32000, // 5
    AAC_SAMPLE_FREQ_24000, // 6
    AAC_SAMPLE_FREQ_22050, // 7
    AAC_SAMPLE_FREQ_16000, // 8
    AAC_SAMPLE_FREQ_12000, // 9
    AAC_SAMPLE_FREQ_11025, // 10
    AAC_SAMPLE_FREQ_8000, // 11
    AAC_SAMPLE_FREQ_7350, // 12
    AAC_SAMPLE_FREQ_EXPLICIT, // 15
} acc_sample_freq_t;

typedef enum aac_chan_t {
    AAC_CHAN_AOT, // 0, Defined in AOT Specifc Config
    AAC_CHAN_ONE, // 1, 1 channel, front center
    AAC_CHAN_TWO, // 2, 2 channels, front left, front right
} aac_chan_t;

typedef struct aac_config_t {
    uint8_t audio_object_type; // 5 bit
    uint8_t sample_freq_index; // 4 bit
    uint8_t channel_config; // 4 bit
    uint8_t frame_length_flag; // 1 bit, For all General Audio Object Types except AAC SSR and ER AAC LD, 0: 1024 samples, 1: 960 samples
} aac_config_t;
