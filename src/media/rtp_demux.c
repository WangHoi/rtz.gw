#include "rtp_demux.h"
#include "sbuf.h"
#include "sdp.h"
#include "codec_types.h"
#include "rtp_types.h"
#include "pack_util.h"
#include "log.h"
#include "h26x.h"
#include "codec_types.h"
#include <stdlib.h>
#include <string.h>

enum {
    RTP_DEMUX_VBUF_SIZE = 1024 * 1024,
    RTP_DEMUX_ABUF_SIZE = 64 * 1024,
    RTP_DEMUX_MAX_XPS_SIZE = 4096,
    RTP_DEMUX_MAX_UNITS = 8,
};

struct rtp_time_info {
    uint32_t start_timestamp;
    uint32_t last_timestamp;
    uint16_t last_seq;
    uint32_t loop;
    int64_t ntp_ts;
    int64_t default_duration;
    int loop_bottom;
    int process_rtp_info;
};

struct rtp_demux_t {
    sbuf_t *vbuf, *abuf;
    struct rtp_time_info vtime, atime;
    video_codec_t *vcodec;
    audio_codec_t *acodec;
    int vpayload, apayload;
    int found_vstart;
    void *udata;
    rtp_demux_video_cb vcb;
    rtp_demux_audio_cb acb;
    nalu_part_t nalus[RTP_DEMUX_MAX_UNITS];
};

static void rtp_time_info_reset(struct rtp_time_info *t);
static void rtp_h264_demux(rtp_demux_t *ctx, const void *data, size_t size);

rtp_demux_t *rtp_demux_new()
{
    rtp_demux_t *ctx = malloc(sizeof(rtp_demux_t));
    memset(ctx, 0, sizeof(rtp_demux_t));
    ctx->vbuf = sbuf_new1(RTP_DEMUX_VBUF_SIZE);
    ctx->abuf = sbuf_new1(RTP_DEMUX_ABUF_SIZE);
    rtp_time_info_reset(&ctx->vtime);
    rtp_time_info_reset(&ctx->atime);
    ctx->vcodec = video_codec_new();
    ctx->acodec = audio_codec_new();
    ctx->found_vstart = 0;
    ctx->udata = NULL;
    ctx->vcb = NULL;
    ctx->acb = NULL;
    ctx->vpayload = -1;
    ctx->apayload = -1;
    return ctx;
}
void rtp_demux_reset(rtp_demux_t *ctx)
{
    ctx->vpayload = -1;
    ctx->apayload = -1;
    ctx->found_vstart = 0;
    sbuf_clear(ctx->vbuf);
    sbuf_clear(ctx->abuf);
    video_codec_reset(ctx->vcodec);
    audio_codec_reset(ctx->acodec);
    rtp_time_info_reset(&ctx->vtime);
    rtp_time_info_reset(&ctx->atime);
}
void rtp_demux_set_userdata(rtp_demux_t *ctx, void *udata)
{
    ctx->udata = udata;
}
void rtp_demux_set_video_cb(rtp_demux_t *ctx, rtp_demux_video_cb func)
{
    ctx->vcb = func;
}
void rtp_demux_set_audio_cb(rtp_demux_t *ctx, rtp_demux_audio_cb func)
{
    ctx->acb = func;
}
void rtp_demux_del(rtp_demux_t *ctx)
{
    sbuf_del(ctx->vbuf);
    sbuf_del(ctx->abuf);
    video_codec_del(ctx->vcodec);
    audio_codec_del(ctx->acodec);
    free(ctx);
}

void rtp_demux_input(rtp_demux_t *ctx, const void *data, size_t size)
{
    const rtp_header_t *hdr = data;
    int64_t ntp_ts = 0;
    uint32_t timestamp = unpack_be32(&hdr->timestamp);
    size_t rtp_hdr_size;
    size_t payload_size;
    if (hdr->extension) {
        const rtp_header_ext_t *xhdr = data + sizeof(rtp_header_t);
        rtp_hdr_size = sizeof(rtp_header_t) + 4 * unpack_be16(&xhdr->length_words_minus1) + 4;
        if (unpack_be16(&xhdr->profile) == 0xabac) {
            rtp_header_ext_abac_t *abac = (void*)xhdr + sizeof(rtp_header_ext_t);
            ntp_ts = (int64_t)unpack_be64(&abac->ntp_hi);
        }
    } else {
        rtp_hdr_size = sizeof(rtp_header_t);
    }
    if (hdr->payload == ctx->vpayload) {
        ctx->vtime.ntp_ts = ntp_ts;
        ctx->vtime.last_timestamp = timestamp;
        if (ctx->vcodec->type == VIDEO_CODEC_H264) {
            rtp_h264_demux(ctx, data + rtp_hdr_size, size - rtp_hdr_size);
        }
    } else if (hdr->payload == ctx->apayload) {
        ctx->atime.ntp_ts = ntp_ts;
        ctx->atime.last_timestamp = timestamp;
    }
}

void rtp_demux_sdp(rtp_demux_t *ctx, sdp_t *sdp)
{
    rtp_demux_reset(ctx);
    sdp_track_t *trak = sdp_get_video_track(sdp);
    if (trak) {
        const char *codec = sdp_track_get_codec(trak);
        if (!strcmp(codec, "H264"))
            ctx->vcodec->type = VIDEO_CODEC_H264;
        else if (!strcmp(codec, "H265") || !strcmp(codec, "HEVC"))
            ctx->vcodec->type = VIDEO_CODEC_H265;
        ctx->vcodec->time_base = sdp_track_get_sample_rate(trak);
        ctx->vpayload = sdp_track_get_payload(trak);
        ctx->vtime.default_duration = 3600;
    }
    trak = sdp_get_audio_track(sdp);
    if (trak) {
        const char *codec = sdp_track_get_codec(trak);
        if (!strcmp(codec, "PCMU")) {
            ctx->acodec->type = AUDIO_CODEC_PCMU;
            ctx->acodec->bits_per_sample = 8;
        } else if (!strcmp(codec, "PCMA")) {
            ctx->acodec->type = AUDIO_CODEC_PCMA;
            ctx->acodec->bits_per_sample = 8;
        } else if (!strcmp(codec, "PCM")) {
            ctx->acodec->type = AUDIO_CODEC_PCM;
            ctx->acodec->bits_per_sample = 16;
        } else if (!strcmp(codec, "ADPCM")) {
            ctx->acodec->type = AUDIO_CODEC_ADPCM;
            ctx->acodec->bits_per_sample = 4;
        } else if (!strcmp(codec, "mpeg4-generic")) {
            ctx->acodec->type = AUDIO_CODEC_AAC;
            ctx->acodec->bits_per_sample = 0;
            // TODO(someday): parse aac_config_t from fmtp
        }
        ctx->acodec->num_channels = atoi(sdp_track_get_codec_param(trak));
        ctx->acodec->sample_rate = sdp_track_get_sample_rate(trak);
        ctx->apayload = sdp_track_get_payload(trak);
        // TODO: fix duration
        ctx->atime.default_duration = 320;
    }
}

void rtp_time_info_reset(struct rtp_time_info *t)
{
    memset(t, 0, sizeof(struct rtp_time_info));
}

void rtp_h264_demux(rtp_demux_t *ctx, const void *data, size_t size)
{
    const h264_nalu_header_t *nalu_h = data;
    int n;
    if (nalu_h->type == H264_NALU_FRAGA) {
        const h264_fu_indicator_t *fu_ind = data;
        const h264_fu_header_t *fu_type = data + 1;
        //log_info("frag t={} s={} e={}", (int)fu_type->type, (int)fu_type->s, (int)fu_type->e);
        if (fu_type->s) {
            ctx->found_vstart = 1;
            h264_nalu_header_t real_nalu_h;
            real_nalu_h.f = fu_ind->f;
            real_nalu_h.nri = fu_ind->nri;
            real_nalu_h.type = fu_type->type;
            sbuf_append2(ctx->vbuf, (char*)&real_nalu_h, sizeof(h264_nalu_header_t));
        }
        if (ctx->found_vstart) {
            sbuf_append2(ctx->vbuf, data + 2, size - 2);
            if (fu_type->e) {
                //LLOG(LL_DEBUG, "ftype: %d", (int)(ctx->vbuf->data[0] & 0x1f));
                n = extract_h26x_nalus(ctx->vbuf->data, ctx->vbuf->size,
                                       ctx->nalus, RTP_DEMUX_MAX_UNITS);
                if (n > 0 && ctx->vcb)
                    ctx->vcb(ctx->vtime.last_timestamp, ctx->vtime.ntp_ts,
                             ctx->vtime.default_duration, ctx->nalus, n, ctx->udata);
                sbuf_clear(ctx->vbuf);
            }
        }
    } else {
        //LLOG(LL_DEBUG, "type: %d", (int)nalu_h->type);
        sbuf_append2(ctx->vbuf, data, size);
        n = extract_h26x_nalus(ctx->vbuf->data, ctx->vbuf->size,
                               ctx->nalus, RTP_DEMUX_MAX_UNITS);
        if (n > 0 && ctx->vcb)
            ctx->vcb(ctx->vtime.last_timestamp, ctx->vtime.ntp_ts,
                     ctx->vtime.default_duration, ctx->nalus, n, ctx->udata);
        sbuf_clear(ctx->vbuf);
    }
}
