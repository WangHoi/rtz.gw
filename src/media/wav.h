#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#pragma pack(push, 1)
// All fields in Little endian
struct wav_header
{
    uint32_t chunk_id;          // "RIFF" = 0x52494646
    uint32_t chunk_size;        // 36+SubChunk2Size = 4+(8+SubChunk1Size)+(8+SubChunk2Size)
    uint32_t format;            // "WAVE" = 0x57415645
    uint32_t sub_chunk1_id;     // "fmt " = 0x666d7420
    uint32_t sub_chunk1_size;   // 16 for PCM
    uint16_t audio_format;      // PCM = 1, PCMA = 6, PCMU = 7
    uint16_t num_channels;      // Mono = 1, Stereo = 2...
    uint32_t sample_rate;       // 8000, 44100...
    uint32_t byte_rate;         // SampleRate*NumChannels*BitsPerSample/8
    uint16_t block_align;       // NumChannels*BitsPerSample/8
    uint16_t bits_per_sample;   // 8 bits = 8, 16 bits = 16
    uint32_t sub_chunk2_id;     // "data" = 0x64617461
    uint32_t sub_chunk2_size;   // data size = NumSamples*NumChannels*BitsPerSample/8
};
#pragma pack(pop)
