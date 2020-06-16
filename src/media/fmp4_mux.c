#include "fmp4_mux.h"
#include "sbuf.h"
#include "pack_util.h"
#include "flac_util.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_SAMPLE_SIZE 400

typedef struct fmp4_sample_info_t {
    int64_t pts;
    int32_t duration;
    int key_frame;
    int offset;
    int size;
} fmp4_sample_info_t;

struct fmp4_mux_t {
    unsigned seq;
    sbuf_t *moof_buf;
    sbuf_t *data_buf[2];
    int sample_count[2];
    fmp4_sample_info_t samples[2][MAX_SAMPLE_SIZE];
};

static int write_box(char *p, const char *name, uint32_t size);
static int write_fullbox(char *p, const char *name, uint32_t size,
    int version, int flags);
static int write_fourcc(char *p, const char *cc);
static int write_trak_video(char *p, int width, int height,
    const char *avcc_data, int avcc_size);
static int write_trak_audio(char *p, const char *dfla_data, int dfla_size);
static int write_trex(char *p, int idx);
static int write_traf(fmp4_mux_t *ctx, char *p, int idx,
    char **out_data_offset_ptr);

void fmp4_mux_init_seg(sbuf_t *b, unsigned duration,
    int width, int height, const void *vcodec_data, int vcodec_size,
    int has_audio, const void *acodec_data, int acodec_size)
{
    sbuf_clear(b);
    sbuf_reserve(b, 2048 + vcodec_size);
    char *p = b->data;
    int i;

    // write 'ftyp' + 'moov' box
    p += write_box(p, "ftyp", 28);
    p += write_fourcc(p, "mp42");
    p += pack_be32(p, 1);
    p += write_fourcc(p, "mp42");
    p += write_fourcc (p, "dash");
    p += write_fourcc(p, "cmfl");
    char *moov_size_ptr = p;
    p += write_box(p, "moov", 0);
    {
        p += write_fullbox(p, "mvhd", 108, 0, 0);
        p += pack_be32(p, 0); // creation_time
        p += pack_be32(p, 0); // modification_time
        p += pack_be32(p, 1000); // timescale
        p += pack_be32(p, duration * 1000); // duration
        p += pack_be32(p, 0x10000); // rate: 1.0
        p += pack_be16(p, 0x100); // volume: 1.0
        p += pack_be16(p, 0); // reserved
        p += pack_be32(p, 0); p += pack_be32(p, 0); // reserved[2]
        p += pack_be32(p, 0x10000); // matrix[0]
        p += pack_be32(p, 0); // matrix[1]
        p += pack_be32(p, 0); // matrix[2]
        p += pack_be32(p, 0); // matrix[3]
        p += pack_be32(p, 0x10000); // matrix[4]
        p += pack_be32(p, 0); // matrix[5]
        p += pack_be32(p, 0); // matrix[6]
        p += pack_be32(p, 0); // matrix[7]
        p += pack_be32(p, 0x40000000); // matrix[8]
        for (i = 0; i < 6; ++i)
            p += pack_be32(p, 0); // pre_defined
        p += pack_be32(p, 2); // next_track_id

        p += write_trak_video(p, width, height, vcodec_data, vcodec_size);
        if (has_audio)
            p += write_trak_audio(p, acodec_data, acodec_size);

        char *mvex_size_ptr = p;
        p += write_box(p, "mvex", 0);
        {
            //write_fullbox(p, "mehd", 16, 0, 0);
            //p += pack_be32(p, 0); // fragment_duration
            p += write_trex(p, 0);
            if (has_audio)
                p += write_trex(p, 1);
        }
        pack_be32(mvex_size_ptr, p - mvex_size_ptr);
    }
    pack_be32(moov_size_ptr, p - moov_size_ptr);
    *p = 0;
    b->size = p - b->data;
}

int write_box(char *p, const char *name, uint32_t size)
{
    *p++ = (size & 0xff000000) >> 24;
    *p++ = (size & 0xff0000) >> 16;
    *p++ = (size & 0xff00) >> 8;
    *p++ = (size & 0xff);
    *p++ = name[0];
    *p++ = name[1];
    *p++ = name[2];
    *p++ = name[3];
    return 8;
}
int write_fullbox(char *p, const char *name, uint32_t size, int version, int flags)
{
    char *const pstart = p;
    p += write_box(p, name, size);
    *p++ = version;
    *p++ = (flags & 0xff0000) >> 16;
    *p++ = (flags & 0xff00) >> 8;
    *p++ = (flags & 0xff);
    return p - pstart;
}
int write_fourcc(char *p, const char *cc)
{
    *p++ = cc[0];
    *p++ = cc[1];
    *p++ = cc[2];
    *p++ = cc[3];
    return 4;
}

int write_trak_video(char *p, int width, int height, const char *avcc_data, int avcc_size)
{
    int i;
    char *const trak_size_ptr = p;
    p += write_box(p, "trak", 0);
    {
        p += write_fullbox(p, "tkhd", 92, 0, 7); // Track_enabled | Track_in_movie | Track_in_preview
        p += pack_be32(p, 0); // creation_time;
        p += pack_be32(p, 0); // modification_time;
        p += pack_be32(p, 1); // track_id;
        p += pack_be32(p, 0); // reserved0;
        p += pack_be32(p, 0); // duration
        p += pack_be32(p, 0); // reserved1[0];
        p += pack_be32(p, 0); // reserved1[1];

        p += pack_be16(p, 0); // layer;
        p += pack_be16(p, 0); // alternate_group;
        p += pack_be16(p, 0); // volume;
        p += pack_be16(p, 0); // reserved2;

        p += pack_be32(p, 0x10000); // matrix[0];
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0x10000); // matrix[4];
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0x40000000); // matrix[8];

        p += pack_be32(p, width << 16); // 16.16 fixed-point
        p += pack_be32(p, height << 16); // 16.16 fixed-point

        char *mdia_size_ptr = p;
        p += write_box(p, "mdia", 0);
        {
            p += write_fullbox(p, "mdhd", 32, 0, 0);
            p += pack_be32(p, 0); // creation_time;
            p += pack_be32(p, 0); // modification_time;
            p += pack_be32(p, 90000); // time_base
            p += pack_be32(p, 0); // total_duration
            p += pack_be16(p, 0x55c4); // language: und
            p += pack_be16(p, 0);

            p += write_fullbox(p, "hdlr", 36, 0, 0);
            p += pack_be32(p, 0); // pre_defined;
            p += write_fourcc(p, "vide"); // handler_type;
            p += pack_be32(p, 0); // reserved[0];
            p += pack_be32(p, 0); // reserved[1];
            p += pack_be32(p, 0); // reserved[2];
            *p++ = 'v';
            *p++ = 'd';
            *p++ = 'o';
            *p++ = 0;

            char *minf_size_ptr = p;
            p += write_box(p, "minf", 0);
            {
                p += write_fullbox(p, "vmhd", 20, 0, 1);
                p += pack_be32(p, 0); // graphicsmode
                p += pack_be32(p, 0); // opcolor
                p += write_box(p, "dinf", 36);
                {
                    p += write_fullbox(p, "dref", 28, 0, 0);
                    p += pack_be32(p, 1); // entry_count
                    p += write_fullbox(p, "url ", 12, 0, 1);
                }
                char *stbl_size_ptr = p;
                p += write_box(p, "stbl", 0);
                {
                    char *stsd_size_ptr = p;
                    p += write_fullbox(p, "stsd", 0, 0, 0);
                    p += pack_be32(p, 1); // entry_count
                    {
                        // VIDEO_CODEC_H264
                        {
                            char *avc1_size_ptr = p;
                            p += write_box(p, "avc1", 0);
                            p += pack_be32(p, 0);
                            p += pack_be16(p, 0);
                            p += pack_be16(p, 1);

                            p += pack_be32(p, 0);
                            p += pack_be32(p, 0);
                            p += pack_be32(p, 0);
                            p += pack_be32(p, 0);
                            p += pack_be16(p, width);
                            p += pack_be16(p, height);
                            p += pack_be32(p, 72 << 16); // horiz_resolution
                            p += pack_be32(p, 72 << 16); // vert_resolution
                            p += pack_be32(p, 0);
                            p += pack_be16(p, 1);

                            for (i = 0; i < 8; ++i)
                                p += pack_be32(p, 0); // compressor_name
                            p += pack_be16(p, 24);
                            p += pack_be16(p, 0xffff);

                            p += write_box(p, "avcC", 8 + avcc_size);
                            memcpy(p, avcc_data, avcc_size);
                            p += avcc_size;

                            pack_be32(avc1_size_ptr, p - avc1_size_ptr);
                        }
                    }
                    pack_be32(stsd_size_ptr, p - stsd_size_ptr);
                    p += write_fullbox(p, "stts", 16, 0, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stsc", 16, 0, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stsz", 20, 0, 0);
                    p += pack_be32(p, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stco", 16, 0, 0);
                    p += pack_be32(p, 0);
                }
                pack_be32(stbl_size_ptr, p - stbl_size_ptr);
            }
            pack_be32(minf_size_ptr, p - minf_size_ptr);
        }
        pack_be32(mdia_size_ptr, p - mdia_size_ptr);
    }
    pack_be32(trak_size_ptr, p - trak_size_ptr);
    return p - trak_size_ptr;
}

int write_trak_audio(char *p, const char *dfla_data, int dfla_size)
{
    struct FLACMetadataStreamInfo info;
    int i;
    /**
     * struct FLACMetadataBlock {
     *      unsigned int(1) LastMetadataBlockFlag;
     *      unsigned int(7) BlockType;
     *      unsigned int(24) Length;
     *      unsigned int(8) BlockData[Length];
     * }
     */
    unpack_flac_metadata_stream_info(dfla_data + 4, &info); // skip block header
    char *const trak_size_ptr = p;
    p += write_box(p, "trak", 0);
    {
        p += write_fullbox(p, "tkhd", 92, 0, 7); // Track_enabled | Track_in_movie | Track_in_preview
        p += pack_be32(p, 0); // creation_time;
        p += pack_be32(p, 0); // modification_time;
        p += pack_be32(p, 2); // track_id;
        p += pack_be32(p, 0); // reserved0;
        p += pack_be32(p, 0); // duration
        p += pack_be32(p, 0); // reserved1[0];
        p += pack_be32(p, 0); // reserved1[1];

        p += pack_be16(p, 0); // layer;
        p += pack_be16(p, 0); // alternate_group;
        p += pack_be16(p, 0x0100); // volume;
        p += pack_be16(p, 0); // reserved2;

        p += pack_be32(p, 0x10000); // matrix[0];
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0x10000); // matrix[4];
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0);
        p += pack_be32(p, 0x40000000); // matrix[8];

        p += pack_be32(p, 0); // 16.16 fixed-point
        p += pack_be32(p, 0); // 16.16 fixed-point

        char *mdia_size_ptr = p;
        p += write_box(p, "mdia", 0);
        {
            p += write_fullbox(p, "mdhd", 32, 0, 0);
            p += pack_be32(p, 0); // creation_time;
            p += pack_be32(p, 0); // modification_time;
            p += pack_be32(p, info.sample_rate); // time_base
            p += pack_be32(p, 0); // total_duration
            p += pack_be16(p, 0x55c4); // language: und
            p += pack_be16(p, 0);

            p += write_fullbox(p, "hdlr", 36, 0, 0);
            p += pack_be32(p, 0); // pre_defined;
            p += write_fourcc(p, "soun"); // handler_type;
            p += pack_be32(p, 0); // reserved[0];
            p += pack_be32(p, 0); // reserved[1];
            p += pack_be32(p, 0); // reserved[2];
            *p++ = 'a';
            *p++ = 'd';
            *p++ = 'o';
            *p++ = 0;

            char *minf_size_ptr = p;
            p += write_box(p, "minf", 0);
            {
                p += write_fullbox(p, "smhd", 16, 0, 0);
                p += pack_be32(p, 0); // balance, reserved
                p += write_box(p, "dinf", 36);
                {
                    p += write_fullbox(p, "dref", 28, 0, 0);
                    p += pack_be32(p, 1); // entry_count
                    p += write_fullbox(p, "url ", 12, 0, 1);
                }
                char *stbl_size_ptr = p;
                p += write_box(p, "stbl", 0);
                {
                    char *stsd_size_ptr = p;
                    p += write_fullbox(p, "stsd", 0, 0, 0);
                    p += pack_be32(p, 1); // entry_count
                    {
                        // FLAC
                        {
                            char *flac_size_ptr = p;
                            p += write_box(p, "fLaC", 0);
                            p += pack_be32(p, 0); // reserved[6]
                            p += pack_be16(p, 0);
                            p += pack_be16(p, 1); // data_reference_index

                            p += pack_be32(p, 0); // reserved0[4]
                            p += pack_be32(p, 0); // reserved1[4]
                            p += pack_be16(p, info.channels);
                            p += pack_be16(p, info.bits_per_sample);
                            p += pack_be32(p, 0);
                            p += pack_be32(p, info.sample_rate << 16);

                            p += write_fullbox(p, "dfLa", dfla_size + 12, 0, 0);
                            memcpy(p, dfla_data, dfla_size);
                            p += dfla_size;

                            pack_be32(flac_size_ptr, p - flac_size_ptr);
                        }
                    }
                    pack_be32(stsd_size_ptr, p - stsd_size_ptr);
                    p += write_fullbox(p, "stts", 16, 0, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stsc", 16, 0, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stsz", 20, 0, 0);
                    p += pack_be32(p, 0);
                    p += pack_be32(p, 0);
                    p += write_fullbox(p, "stco", 16, 0, 0);
                    p += pack_be32(p, 0);
                }
                pack_be32(stbl_size_ptr, p - stbl_size_ptr);
            }
            pack_be32(minf_size_ptr, p - minf_size_ptr);
        }
        pack_be32(mdia_size_ptr, p - mdia_size_ptr);
    }
    pack_be32(trak_size_ptr, p - trak_size_ptr);
    return p - trak_size_ptr;
}

fmp4_mux_t * fmp4_mux_new()
{
    fmp4_mux_t *ctx = malloc(sizeof(fmp4_mux_t));
    memset(ctx, 0, sizeof(fmp4_mux_t));
    ctx->moof_buf = sbuf_new1(4096);
    ctx->data_buf[0] = sbuf_new();
    ctx->data_buf[1] = sbuf_new();
    return ctx;
}

void fmp4_mux_del(fmp4_mux_t * ctx)
{
    sbuf_del(ctx->moof_buf);
    sbuf_del(ctx->data_buf[0]);
    sbuf_del(ctx->data_buf[1]);
    free(ctx);
}

void fmp4_mux_media_start(fmp4_mux_t * ctx)
{
    ctx->sample_count[0] = ctx->sample_count[1] = 0;
    assert(sizeof(ctx->samples) >= 2 * MAX_SAMPLE_SIZE * sizeof(fmp4_sample_info_t));
    memset(ctx->samples, 0, sizeof(ctx->samples));
    sbuf_clear(ctx->data_buf[0]);
    sbuf_clear(ctx->data_buf[1]);
}

void fmp4_mux_media_sample(fmp4_mux_t * ctx,
    int video, int64_t pts, int32_t duration,
    int key_frame, const char *data, int size)
{
    int track_idx = video ? 0 : 1;
    //LLOG(LL_DEBUG, "#%d pts=%lld key=%d size=%d", track_idx, (long long)pts, key_frame, size);
    assert(ctx->sample_count[track_idx] < MAX_SAMPLE_SIZE);
    if (ctx->sample_count[track_idx] >= MAX_SAMPLE_SIZE) {
        LLOG(LL_ERROR, "#%d pts=%lld key=%d size=%d exceeds fragment's sample limit.",
            track_idx, (long long)pts, key_frame, size);
        return;
    }
    int sample_idx = ctx->sample_count[track_idx]++;
    fmp4_sample_info_t *sample = &ctx->samples[track_idx][sample_idx];
    sbuf_t *data_buf = ctx->data_buf[track_idx];

    if (video && sample_idx > 0) {
        fmp4_sample_info_t *last_sample = &ctx->samples[track_idx][sample_idx - 1];
        if (last_sample->pts < pts)
            last_sample->duration = pts - last_sample->pts;
    }

    sample->key_frame = key_frame;
    sample->pts = pts;
    sample->duration = duration;
    sample->offset = data_buf->size;
    if (video) {
        /* Write nalu size */
        sample->size = 4 + size;
        sbuf_makeroom(data_buf, 4 + size);
        data_buf->size += pack_be32(sbuf_tail(data_buf), size);
    } else {
        sample->size = size;
    }
    sbuf_append2(data_buf, data, size);
}

int write_traf(fmp4_mux_t * ctx, char *p, int idx, char **out_data_offset_ptr)
{
    if (ctx->sample_count[idx] == 0)
        return 0;

    char *const traf_size_ptr = p;
    int sample_count = ctx->sample_count[idx];
    fmp4_sample_info_t * samples = ctx->samples[idx];
    p += write_box(p, "traf", 0);
    {
        /*
        p += write_fullbox(p, "tfhd", 24, 0, 1);
        p += pack_be32(p, idx + 1);
        // 8 byte base_data_offset
        p += pack_be32(p, 0);
        p += pack_be32(p, static_cast<uint32_t> (file_offset + MOOF_HEADER_SIZE));
        */
        p += write_fullbox(p, "tfhd", 24, 0, 0x020022); // default_base_is_moof, sample_description_index_present, default_sample_flags_present
        p += pack_be32(p, idx + 1); // track_index
        p += pack_be32(p, 1); // sample_description_index;
        p += pack_be32(p, 0); // default_sample_flags

        int64_t base_pts = samples[0].pts;
        p += write_fullbox(p, "tfdt", 20, 1, 0);
        p += pack_be32(p, base_pts >> 32);
        p += pack_be32(p, base_pts & 0xffffffff);

        char *const trun_size_ptr = p;
        // data-offset-present; sample-duration-present; sample-size-present; sample-flags-present;
        p += write_fullbox(p, "trun", 0, 0, 0x701);
        p += pack_be32(p, sample_count);
        *out_data_offset_ptr = p;
        p += pack_be32(p, 0); // data_offset to be patched later

        /* sample_flag:
            for video i-frame:
                sample_depends_on = 2
                sample_is_depended_on = 1
                sample_has_redundancy = 2
            for video p-frame:
                sample_depends_on = 1
                sample_is_depended_on = 1
                sample_has_redundancy = 2
                is_differential_sample = 1
            for audio frame:
                sample_depends_on = 2
                sample_is_depended_on = 2
                sample_has_redundancy = 2 */
        int i;
        for (i = 0; i < sample_count; ++i) {
            p += pack_be32(p, samples[i].duration);
            p += pack_be32(p, samples[i].size);
            uint32_t sample_flags = 0;
            if (idx == 0) {
                if (samples[i].key_frame)
                    sample_flags = (2 << 24) | (1 << 22) | (2 << 20);
                else
                    sample_flags = (1 << 24) | (1 << 22) | (2 << 20) | (1 << 16);
            } else {
                sample_flags = (2 << 24) | (2 << 22) | (2 << 20);
            }
            p += pack_be32(p, sample_flags);
        }
        pack_be32(trun_size_ptr, p - trun_size_ptr);
    }
    pack_be32(traf_size_ptr, p - traf_size_ptr);
    return p - traf_size_ptr;
}

void fmp4_mux_media_end(fmp4_mux_t *ctx,
    unsigned seq, int64_t next_video_pts,
    sbuf_t *buf, double *out_duration)
{
    ctx->seq = seq;
    if (ctx->sample_count[0] > 0) {
        fmp4_sample_info_t *last_sample = &ctx->samples[0][ctx->sample_count[0] - 1];
        if (last_sample->pts < next_video_pts)
            last_sample->duration = next_video_pts - last_sample->pts;
    }

    sbuf_clear(ctx->moof_buf);
    sbuf_makeroom(ctx->moof_buf, 4096 * 4);
    char *p = ctx->moof_buf->data;
    char *const moof_size_ptr = p;
    char *data_offset_ptr[2] = {};
    p += write_box(p, "moof", 0);
    {
        p += write_fullbox(p, "mfhd", 16, 0, 0);
        {
            p += pack_be32(p, ctx->seq);
            //p += pack_be32(p, 0); // set seq to zero
            p += write_traf(ctx, p, 0, &data_offset_ptr[0]);
            p += write_traf(ctx, p, 1, &data_offset_ptr[1]);
        }
    }
    pack_be32(moof_size_ptr, p - moof_size_ptr);
    p += write_box(p, "mdat", 8 + ctx->data_buf[0]->size + ctx->data_buf[1]->size);
    ctx->moof_buf->size = p - ctx->moof_buf->data;

    LLOG(LL_TRACE, "moof size=%lld", (long long)(p - ctx->moof_buf->data));

    /* Backpatch data_offset_ptr */
    if (data_offset_ptr[0])
        pack_be32(data_offset_ptr[0], p - ctx->moof_buf->data);
    if (data_offset_ptr[1])
        pack_be32(data_offset_ptr[1], p - ctx->moof_buf->data + ctx->data_buf[0]->size);
    sbuf_clear(buf);
    sbuf_append(buf, ctx->moof_buf);
    sbuf_append(buf, ctx->data_buf[0]);
    sbuf_append(buf, ctx->data_buf[1]);

    /* Update duration */
    fmp4_sample_info_t *first_sample, *last_sample;
    if (ctx->sample_count[0] > 0) {
        first_sample = &ctx->samples[0][0];
        last_sample = &ctx->samples[0][ctx->sample_count[0] - 1];
        //LLOG(LL_TRACE, "%ld %ld %d", first_sample->pts, last_sample->pts, last_sample->duration);
        *out_duration = (double)(last_sample->pts + last_sample->duration - first_sample->pts) / 90000.0;
    } else if (ctx->sample_count[1] > 0) {
        first_sample = &ctx->samples[1][0];
        last_sample = &ctx->samples[1][ctx->sample_count[1] - 1];
        *out_duration = (double)(last_sample->pts + last_sample->duration - first_sample->pts) / 8000.0;
    } else {
        *out_duration = 0.0;
    }
}

double fmp4_mux_duration(fmp4_mux_t *ctx, int64_t next_video_pts)
{
    /* Update duration */
    fmp4_sample_info_t *first_sample, *last_sample;
    if (ctx->sample_count[0] > 0) {
        first_sample = &ctx->samples[0][0];
        return (double)(next_video_pts - first_sample->pts) / 90000.0;
    } else if (ctx->sample_count[1] > 0) {
        first_sample = &ctx->samples[1][0];
        last_sample = &ctx->samples[1][ctx->sample_count[1] - 1];
        return (double)(last_sample->pts + last_sample->duration - first_sample->pts) / 8000.0;
    }
    return 0.0;
}

int write_trex(char *p, int idx)
{
    p += write_fullbox(p, "trex", 32, 0, 0);
    p += pack_be32(p, 1 + idx); // track_ID;
    p += pack_be32(p, 1); // default_sample_description_index;
    if (idx == 0) {
        //uint32_t default_sample_duration = (_video_codec.frame_rate == 0) ? 3600 : 90000 / _video_codec.frame_rate;
        uint32_t default_sample_duration = 3600;
        p += pack_be32(p, default_sample_duration);
        p += pack_be32(p, 0); // default_sample_size;
        p += pack_be32(p, 0x00010000); // default_sample_flags
    } else { // audio
        p += pack_be32(p, 0); // default_sample_duration
        p += pack_be32(p, 0); // default_sample_size;
        p += pack_be32(p, 0x02000000); // default_sample_flags
    }
    return 32;
}
