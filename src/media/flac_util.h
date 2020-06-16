#pragma once
#include <stdint.h>

enum {
    FLAC_METADATA_STREAMINFO_SIZE = 34,
};

typedef struct sbuf_t sbuf_t;

struct FLACMetadataStreamInfo {
    unsigned min_blocksize, max_blocksize;
    unsigned min_framesize, max_framesize;
    unsigned sample_rate;
    unsigned channels;
    unsigned bits_per_sample;
    uint64_t total_samples;
    uint8_t md5sum[16];
};

/**
 * unpack FLACMetadataStreamInfo, data size min: FLAC_METADATA_STREAMINFO_SIZE
 */
int unpack_flac_metadata_stream_info(const void *data, struct FLACMetadataStreamInfo *info);
int pack_flac_metadata_stream_info(void *data, struct FLACMetadataStreamInfo *info);

sbuf_t *flac_encode_pcma(const void *data, int samples);
sbuf_t *flac_gen_silence(int samples);

