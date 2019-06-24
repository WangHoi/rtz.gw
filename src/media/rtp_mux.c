#include "rtp_mux.h"
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
#include <assert.h>

enum {
    MAX_RTP_PACKET_SIZE = 1400,
};

struct rtp_mux_t {
    void *udata;
    rtp_mux_cb cb;
    uint16_t seqnum[2];
    sbuf_t *sps, *pps;
};

static void rtp_mux_audio(rtp_mux_t *ctx, uint32_t timestamp, const void *data, int size);
static void rtp_mux_h264(rtp_mux_t *ctx, uint32_t timestamp, const void *data, int size);

rtp_mux_t *rtp_mux_new()
{
    rtp_mux_t *ctx = malloc(sizeof(rtp_mux_t));
    memset(ctx, 0, sizeof(rtp_mux_t));
    ctx->sps = sbuf_new1(1024);
    ctx->pps = sbuf_new1(64);
    return ctx;
}
void rtp_mux_reset(rtp_mux_t *ctx)
{
}

void rtp_mux_set_cb(rtp_mux_t *ctx, rtp_mux_cb func, void *udata)
{
    ctx->cb = func;
    ctx->udata = udata;
}
void rtp_mux_del(rtp_mux_t *ctx)
{
    sbuf_del(ctx->sps);
    sbuf_del(ctx->pps);
    free(ctx);
}

void rtp_mux_input(rtp_mux_t *ctx, int video, uint32_t timestamp,
                   const void *data, int size)
{
    if (video)
        rtp_mux_h264(ctx, timestamp, data, size);
    else
        rtp_mux_audio(ctx, timestamp, data, size);
}

void rtp_mux_set_sps_pps(rtp_mux_t *ctx, const void *sps_data, int sps_size, const void *pps_data, int pps_size)
{
    sbuf_strncpy(ctx->sps, sps_data, sps_size);
    sbuf_strncpy(ctx->pps, pps_data, pps_size);
}

void rtp_mux_h264(rtp_mux_t *ctx, uint32_t timestamp, const void *data, int size)
{
    //LLOG(LL_TRACE, "mux_ts=%u size=%d", timestamp, size);
    uint8_t buf[MAX_RTP_PACKET_SIZE];
    const uint8_t *pin = data;
    uint8_t *pout;
    rtp_header_t *hdr;
    int n;
    const int video = 1;
    const h264_nalu_header_t *nalu_hdr = data;

    hdr = (rtp_header_t*)buf;
    memset(hdr, 0, sizeof(rtp_header_t));
    hdr->version = 2;
    hdr->payload = 96;
    pack_be32(&hdr->timestamp, timestamp);

    int kf = (nalu_hdr->type == H264_NALU_IFRAME);

    //LLOG(LL_TRACE, "%d %d %d", (int)nalu_hdr->type, ctx->sps->size, ctx->pps->size);
    if (kf) {
        if (!sbuf_empty(ctx->sps)) {
            /* WebRTC playout-delay extension
             *
             *   0                   1                   2                   3
             *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             *  |  ID   | len=2 |   MIN delay           |   MAX delay           |
             *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
             */
            hdr->extension = 1;
            pack_be32(buf + sizeof(rtp_header_t), 0xbede0001);
             /* Set default MIN/MAX delay, will be rewrite later inside rtz_server.c */
            pack_be32(buf + sizeof(rtp_header_t) + 4, 0x620000c8);

            pack_be16(&hdr->seqnum, ctx->seqnum[video]++);
            memcpy(buf + sizeof(rtp_header_t) + 8, ctx->sps->data, ctx->sps->size);
            if (ctx->cb)
                ctx->cb(video, kf, buf, sizeof(rtp_header_t) + 8 + ctx->sps->size, ctx->udata);

            hdr->extension = 0; /* rtp header will be reused */
        }
        if (!sbuf_empty(ctx->pps)) {
            pack_be16(&hdr->seqnum, ctx->seqnum[video]++);
            memcpy(buf + sizeof(rtp_header_t), ctx->pps->data, ctx->pps->size);
            if (ctx->cb)
                ctx->cb(video, kf, buf, sizeof(rtp_header_t) + ctx->pps->size, ctx->udata);
        }
    }

    pout = buf + sizeof(rtp_header_t);
    pack_be16(&hdr->seqnum, ctx->seqnum[video]++);
    hdr->marker = (size <= MAX_RTP_PACKET_SIZE - (int)sizeof(rtp_header_t)) ? 1 : 0;
    // no fragments
    if (hdr->marker) {
        memcpy(pout, data, size);
        pout += size;
        if (ctx->cb)
            ctx->cb(video, kf, buf, (int)(pout - buf), ctx->udata);
        return;
    }

    h264_fu_indicator_t *fu_ind = (h264_fu_indicator_t*)pout;
    h264_fu_header_t *fu_type = (h264_fu_header_t*)(pout + 1);
    // first fragment
    fu_ind->type = H264_NALU_FRAGA;
    fu_ind->nri = nalu_hdr->nri;
    fu_ind->f = 0;
    fu_type->type = nalu_hdr->type;
    fu_type->s = 1;
    fu_type->e = 0;
    fu_type->r = 0;

    pout = buf + sizeof(rtp_header_t) + 2;
    n = MAX_RTP_PACKET_SIZE - sizeof(rtp_header_t) - 2;
    /* skip first byte (H264 NaluHeader) */
    memcpy(pout, pin + 1, n);
    pout += n;
    pin += n + 1;
    size -= n + 1;
    if (ctx->cb)
        ctx->cb(video, kf, buf, (int)(pout - buf), ctx->udata);

    // remain fragments
    while (size > 0) {
        pout = buf + sizeof(rtp_header_t) + 2;
        n = MAX_RTP_PACKET_SIZE - sizeof(rtp_header_t) - 2;
        pack_be16(&hdr->seqnum, ctx->seqnum[video]++);
        hdr->marker = (size <= n) ? 1 : 0;
        if (n > size)
            n = size;
        fu_type->s = 0;
        fu_type->e = (n == size) ? 1 : 0;
        memcpy(pout, pin, n);
        pout += n;
        pin += n;
        size -= n;
        if (ctx->cb)
            ctx->cb(video, kf, buf, (int)(pout - buf), ctx->udata);
    }
}

void rtp_mux_audio(rtp_mux_t *ctx, uint32_t timestamp, const void *data, int size)
{
    assert(size + sizeof(rtp_header_t) <= MAX_RTP_PACKET_SIZE);

    uint8_t buf[MAX_RTP_PACKET_SIZE];
    rtp_header_t *hdr;
    const int video = 0;

    hdr = (rtp_header_t*)buf;
    memset(hdr, 0, sizeof(rtp_header_t));
    hdr->version = 2;
    hdr->payload = 8; // PCMA
    pack_be16(&hdr->seqnum, ctx->seqnum[video]++);
    pack_be32(&hdr->timestamp, timestamp);
    hdr->marker = 1;
    memcpy(buf + sizeof(rtp_header_t), data, size);
    if (ctx->cb)
        ctx->cb(video, 1, buf, sizeof(rtp_header_t) + size, ctx->udata);
}
