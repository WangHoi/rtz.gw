#include "ps_rtp_demux.h"
#include "rtp_types.h"
#include "h26x.h"
#include "log.h"
#include "sbuf.h"
#include "pack_util.h"
#include <stdlib.h>
#include <string.h>

enum {
    RTP_DEMUX_BUF_SIZE = 1024 * 1024,
    RTP_DEMUX_MAX_UNITS = 8,
};

struct ps_rtp_demux_t {
    sbuf_t *ps_buf, *vbuf;
    //struct rtp_time_info vtime, atime;
    //video_codec_t *vcodec;
    //audio_codec_t *acodec;
    //int vpayload, apayload;
    //int found_vstart;
    uint16_t seq;
    uint32_t timestamp;
    void *udata;
    ps_rtp_demux_video_cb vcb;
    ps_rtp_demux_audio_cb acb;
    nalu_part_t nalus[RTP_DEMUX_MAX_UNITS];
};

static void ps_input(ps_rtp_demux_t *ctx);
static void flush_vbuf(ps_rtp_demux_t *ctx);


ps_rtp_demux_t *ps_rtp_demux_new()
{
    ps_rtp_demux_t *ctx = malloc(sizeof(ps_rtp_demux_t));
    memset(ctx, 0, sizeof(ps_rtp_demux_t));
    ctx->ps_buf = sbuf_new1(RTP_DEMUX_BUF_SIZE);
    ctx->vbuf = sbuf_new1(RTP_DEMUX_BUF_SIZE);
    ctx->udata = NULL;
    ctx->vcb = NULL;
    ctx->acb = NULL;
    ctx->seq = UINT16_MAX;
    ctx->timestamp = UINT32_MAX;
    return ctx;

}

void ps_rtp_demux_reset(ps_rtp_demux_t *ctx)
{
    ctx->seq = UINT16_MAX;
    ctx->timestamp = UINT32_MAX;
}

void ps_rtp_demux_set_userdata(ps_rtp_demux_t *ctx, void *udata)
{
    ctx->udata = udata;
}

void ps_rtp_demux_set_video_cb(ps_rtp_demux_t *ctx, ps_rtp_demux_video_cb func)
{
    ctx->vcb = func;
}

void ps_rtp_demux_set_audio_cb(ps_rtp_demux_t *ctx, ps_rtp_demux_audio_cb func)
{
    ctx->acb = func;
}

void ps_rtp_demux_del(ps_rtp_demux_t *ctx)
{
    sbuf_del(ctx->ps_buf);
    sbuf_del(ctx->vbuf);
    free(ctx);
}

void ps_rtp_demux_input(ps_rtp_demux_t *ctx, const void *data, size_t size)
{
    // validate rtp header
    const rtp_header_t *hdr = data;
    if (hdr->version != 2)
        return;
    int hdr_len = sizeof(rtp_header_t); // 12
    hdr_len += 4 * hdr->cc;
    if (hdr->extension) {
        if (size < hdr_len + 4)
            return;
        hdr_len += 4 * unpack_be16(data + hdr_len);
    }
    if (size < hdr_len)
        return;

    const char *payload = data + hdr_len;
    int payload_len = (int)size - hdr_len;
    uint16_t seq = unpack_be16(&hdr->seqnum);
    uint32_t timestamp = unpack_be32(&hdr->timestamp);
    if (ctx->timestamp != timestamp) {
        if (!sbuf_empty(ctx->ps_buf)) {
            ps_input(ctx);
            sbuf_clear(ctx->ps_buf);
        }
    }
    ctx->seq = seq;
    ctx->timestamp = timestamp;
    sbuf_append2(ctx->ps_buf, payload, payload_len);

    if (hdr->marker || ctx->ps_buf->size >= RTP_DEMUX_BUF_SIZE) {
        ps_input(ctx);
        sbuf_clear(ctx->ps_buf);
    }
}

void ps_input(ps_rtp_demux_t *ctx)
{
    const char *p = ctx->ps_buf->data;
    const char *const pend = p + ctx->ps_buf->size;
    while (p + 6 <= pend) {
        uint32_t start_code = unpack_be32 (p);
        //LLOG(LL_TRACE, "  start_code=%08x", start_code);
        if (start_code == 0x01ba) { // pack_header(): ISO 13818-1: Table 2-33
            flush_vbuf(ctx);
            if (pend - p < 14)
                break;
            int pack_header_size = 14 + (p[13] & 7);
            if (pend - p < pack_header_size)
                break;
            p += pack_header_size;
        } else if (start_code == 0x01bb) { // system_header(): ISO 13818-1: Table 2-34
            int sys_header_size = 6 + unpack_be16(p + 4);
            if (pend - p < sys_header_size)
                break;
            p += sys_header_size;
        } else { // other pes_packet(): ISO 13818-1: Table 2-17
            int pes_packet_header_size = unpack_be16(p + 4);
            if (pend - p < 6 + pes_packet_header_size)
                break;

            int is_video = (start_code >= 0x01e0 && start_code <= 0x01ef);
            int is_audio = (start_code >= 0x01c0 && start_code <= 0x01df);
            if (is_video || is_audio) {
                int hdr_size = 9 + p[8];
                int data_alignment_indicator = p[6] & 4;
                const char *payload_data = p + hdr_size;
                int payload_size = 6 + pes_packet_header_size - hdr_size;
                if (pes_packet_header_size < hdr_size)
                    break;
                //log_trace ("    data_alignment_indicator={} pes_pkt_size={} payload_data={:02x}{:02x}{:02x}{:02x}",
                //           data_alignment_indicator, pes_packet_header_size,
                //           payload_data[0], payload_data[1], payload_data[2], payload_data[3]);
                if (is_video) {
                    //if (data_alignment_indicator != 0 || _video_buf_size + payload_size > MAX_PS_DEMUX_BUF_SIZE) {
                    //    FlushVideoBuffer (pts);
                    //}
                    sbuf_append2(ctx->vbuf, payload_data, payload_size);
                } else {
                    if (data_alignment_indicator == 0) {
                        LLOG(LL_FATAL, "BUG: fragmented audio.");
                    }
                    if (ctx->acb)
                        ctx->acb(ctx->timestamp, 0, p + hdr_size, 6 + pes_packet_header_size - hdr_size, ctx->udata);
                }
            } else if (start_code == 0x1bc || start_code == 0x1bd) { // program_stream_map or private_stream_1
                flush_vbuf(ctx);
            } else {
                LLOG(LL_TRACE, "ignore stream_id=%08x", start_code);
            }

            p += 6 + pes_packet_header_size;
        }
    }
    flush_vbuf(ctx);
}

void flush_vbuf(ps_rtp_demux_t *ctx)
{
    if (!sbuf_empty(ctx->vbuf)) {
        int n = extract_h26x_nalus(ctx->vbuf->data, ctx->vbuf->size,
                                   ctx->nalus, RTP_DEMUX_MAX_UNITS);
        if (ctx->vcb)
            ctx->vcb(ctx->timestamp, 0, ctx->nalus, n, ctx->udata);
        sbuf_clear(ctx->vbuf);
    }
}
