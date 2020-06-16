#include <string.h>
#include "rtp.h"
#include "rtp_srtp.h"
#include "event_loop.h" // for zl_hrtime()
#include "log.h"

char *rtp_payload(char *buf, int len, int *plen)
{
    if (!buf || len < 12)
        return NULL;

    rtp_header *rtp = (rtp_header *)buf;
    int hlen = 12;
    if (rtp->csrccount)	/* Skip CSRC if needed */
        hlen += rtp->csrccount * 4;

    if (rtp->extension) {
        rtp_header_extension *ext = (rtp_header_extension*)(buf + hlen);
        int extlen = ntohs(ext->length) * 4;
        hlen += 4;
        if (len > (hlen + extlen))
            hlen += extlen;
    }
    if (plen)
        *plen = len - hlen;
    return buf + hlen;
}

int rtp_header_extension_get_id(const char *sdp, const char *extension)
{
    if (!sdp || !extension)
        return -1;
    char extmap[100];
    snprintf(extmap, 100, "a=extmap:%%d %s", extension);
    /* Look for the extmap */
    const char *line = strstr(sdp, "m=");
    while (line) {
        char *next = strchr(line, '\n');
        if (next) {
            *next = '\0';
            if (strstr(line, "a=extmap") && strstr(line, extension)) {
                /* Gotcha! */
                int id = 0;
            #pragma GCC diagnostic ignored "-Wformat-nonliteral"
                if (sscanf(line, extmap, &id) == 1) {
                #pragma GCC diagnostic warning "-Wformat-nonliteral"
                    *next = '\n';
                    return id;
                }
            }
            *next = '\n';
        }
        line = next ? (next + 1) : NULL;
    }
    return -2;
}

const char *rtp_header_extension_get_from_id(const char *sdp, int id)
{
    if (!sdp || id < 0)
        return NULL;
    /* Look for the mapping */
    char extmap[100];
    snprintf(extmap, 100, "a=extmap:%d ", id);
    const char *line = strstr(sdp, "m=");
    while (line) {
        char *next = strchr(line, '\n');
        if (next) {
            *next = '\0';
            if (strstr(line, extmap)) {
                /* Gotcha! */
                char extension[100];
                if (sscanf(line, "a=extmap:%d %s", &id, extension) == 2) {
                    *next = '\n';
                    if (strstr(extension, RTZ_RTP_EXTMAP_AUDIO_LEVEL))
                        return RTZ_RTP_EXTMAP_AUDIO_LEVEL;
                    if (strstr(extension, RTZ_RTP_EXTMAP_VIDEO_ORIENTATION))
                        return RTZ_RTP_EXTMAP_VIDEO_ORIENTATION;
                    if (strstr(extension, RTZ_RTP_EXTMAP_PLAYOUT_DELAY))
                        return RTZ_RTP_EXTMAP_PLAYOUT_DELAY;
                    if (strstr(extension, RTZ_RTP_EXTMAP_TOFFSET))
                        return RTZ_RTP_EXTMAP_TOFFSET;
                    if (strstr(extension, RTZ_RTP_EXTMAP_ABS_SEND_TIME))
                        return RTZ_RTP_EXTMAP_ABS_SEND_TIME;
                    if (strstr(extension, RTZ_RTP_EXTMAP_TRANSPORT_WIDE_CC))
                        return RTZ_RTP_EXTMAP_TRANSPORT_WIDE_CC;
                    if (strstr(extension, RTZ_RTP_EXTMAP_RTP_STREAM_ID))
                        return RTZ_RTP_EXTMAP_RTP_STREAM_ID;
                    LLOG(LL_ERROR, "Unsupported extension '%s'", extension);
                    return NULL;
                }
            }
            *next = '\n';
        }
        line = next ? (next + 1) : NULL;
    }
    return NULL;
}

int rtp_header_extension_find(char *buf, int len, int id,
                              uint8_t *byte, uint32_t *word, char **playout_delay_ext_ref)
{
    if (!buf || len < 12)
        return -1;
    rtp_header *rtp = (rtp_header *)buf;
    int hlen = 12;
    if (rtp->csrccount)	/* Skip CSRC if needed */
        hlen += rtp->csrccount * 4;
    if (rtp->extension) {
        rtp_header_extension *ext = (rtp_header_extension *)(buf + hlen);
        int extlen = ntohs(ext->length) * 4;
        hlen += 4;
        if (len > (hlen + extlen)) {
            /* 1-Byte extension */
            if (ntohs(ext->type) == 0xBEDE) {
                const uint8_t padding = 0x00, reserved = 0xF;
                uint8_t extid = 0, idlen;
                int i = 0;
                while (i < extlen) {
                    extid = buf[hlen + i] >> 4;
                    if (extid == reserved) {
                        break;
                    } else if (extid == padding) {
                        i++;
                        continue;
                    }
                    idlen = (buf[hlen + i] & 0xF) + 1;
                    if (extid == id) {
                        /* Found! */
                        if (byte)
                            *byte = buf[hlen + i + 1];
                        if (word && idlen >= 3 && (i + 3) < extlen) {
                            memcpy(word, buf + hlen + i, sizeof(uint32_t));
                            *word = ntohl(*word);
                        }
                        if (playout_delay_ext_ref)
                            *playout_delay_ext_ref = &buf[hlen + i];
                        return 0;
                    }
                    i += 1 + idlen;
                }
            }
            hlen += extlen;
        }
    }
    return -1;
}

int rtp_header_extension_parse_audio_level(char *buf, int len, int id, int *level)
{
    uint8_t byte = 0;
    if (rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
        return -1;
    /* a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
    int v = (byte & 0x80) >> 7;
    int value = byte & 0x7F;
    LLOG(LL_DEBUG, "%02x --> v=%d, level=%d", byte, v, value);
    if (level)
        *level = value;
    return 0;
}

int rtp_header_extension_parse_video_orientation(char *buf, int len, int id,
                                                 int *c, int *f, int *r1, int *r0)
{
    uint8_t byte = 0;
    if (rtp_header_extension_find(buf, len, id, &byte, NULL, NULL) < 0)
        return -1;
    /* a=extmap:4 urn:3gpp:video-orientation */
    int cbit = (byte & 0x08) >> 3;
    int fbit = (byte & 0x04) >> 2;
    int r1bit = (byte & 0x02) >> 1;
    int r0bit = byte & 0x01;
    LLOG(LL_DEBUG, "%02x --> c=%d, f=%d, r1=%d, r0=%d", byte, cbit, fbit, r1bit, r0bit);
    if (c)
        *c = cbit;
    if (f)
        *f = fbit;
    if (r1)
        *r1 = r1bit;
    if (r0)
        *r0 = r0bit;
    return 0;
}

int rtp_header_extension_parse_playout_delay(char *buf, int len, int id,
                                             uint16_t *min_delay, uint16_t *max_delay) {
    uint32_t bytes = 0;
    if (rtp_header_extension_find(buf, len, id, NULL, &bytes, NULL) < 0)
        return -1;
    /* a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay */
    uint16_t min = (bytes & 0x00FFF000) >> 12;
    uint16_t max = bytes & 0x00000FFF;
    LLOG(LL_DEBUG, "%"SCNu32"x --> min=%"SCNu16", max=%"SCNu16, bytes, min, max);
    if (min_delay)
        *min_delay = min;
    if (max_delay)
        *max_delay = max;
    return 0;
}

int rtp_header_extension_parse_rtp_stream_id(char *buf, int len, int id,
                                             char *sdes_item, int sdes_len)
{
    char *ext = NULL;
    if (rtp_header_extension_find(buf, len, id, NULL, NULL, &ext) < 0)
        return -1;
    /* a=extmap:3/sendonly urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id */
    if (ext == NULL)
        return -2;
    int val_len = (*ext & 0x0F) + 1;
    if (val_len > (sdes_len - 1)) {
        LLOG(LL_WARN, "SDES buffer is too small (%d < %d), RTP stream ID will be cut", val_len, sdes_len);
        val_len = sdes_len - 1;
    }
    if (val_len > len - (ext - buf) - 1) {
        return -3;
    }
    memcpy(sdes_item, ext + 1, val_len);
    *(sdes_item + val_len) = '\0';
    return 0;
}

int rtp_header_extension_parse_transport_wide_cc(char *buf, int len, int id, uint16_t *transSeqNum)
{
    uint32_t bytes = 0;
    if (rtp_header_extension_find(buf, len, id, NULL, &bytes, NULL) < 0)
        return -1;
    /*  0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |  ID   | L=1   |transport-wide sequence number | zero padding  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    *transSeqNum = (bytes & 0x00FFFF00) >> 8;
    return 0;
}

/* RTP context related methods */
void rtz_rtp_switching_context_reset(rtz_rtp_switching_context *context)
{
    if (context == NULL)
        return;
    /* Reset the context values */
    memset(context, 0, sizeof(*context));
}

int rtz_rtp_skew_compensate_audio(rtp_header *header, rtz_rtp_switching_context *context, int64_t now)
{
    /* Reset values if a new ssrc has been detected */
    if (context->a_new_ssrc) {
        LLOG(LL_TRACE, "audio skew SSRC=%"SCNu32" resetting status", context->a_last_ssrc);
        context->a_reference_time = now;
        context->a_start_time = 0;
        context->a_evaluating_start_time = 0;
        context->a_start_ts = 0;
        context->a_active_delay = 0;
        context->a_prev_delay = 0;
        context->a_seq_offset = 0;
        context->a_ts_offset = 0;
        context->a_target_ts = 0;
        context->a_new_ssrc = 0;
    }

    /* N 	: a N sequence number jump has been performed */
    /* 0  	: any new skew compensation has been applied */
    /* -N  	: a N packet drop must be performed */
    int exit_status = 0;

    /* Do not execute skew analysis in the first seconds */
    if (now - context->a_reference_time < SKEW_DETECTION_WAIT_TIME_SECS / 2 * ZL_USEC_PER_SEC) {
        return 0;
    } else if (!context->a_start_time) {
        LLOG(LL_TRACE, "audio skew SSRC=%"SCNu32" evaluation phase start", context->a_last_ssrc);
        context->a_start_time = now;
        context->a_evaluating_start_time = now;
        context->a_start_ts = context->a_last_ts;
    }

    /* Skew analysis */
    /* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
    if (context->a_target_ts > 0 && (int32_t)(context->a_target_ts - context->a_last_ts) > 0) {
        context->a_seq_offset--;
        exit_status = -1;
    } else {
        context->a_target_ts = 0;
        /* Do not execute analysis for out of order packets or multi-packets frame */
        if (context->a_last_seq == context->a_prev_seq + 1 && context->a_last_ts != context->a_prev_ts) {
            /* Set the sample rate according to the header */
            uint32_t akhz = 48; /* 48khz for Opus */
            if (header->type == 0 || header->type == 8 || header->type == 9)
                akhz = 8;
            /* Evaluate the local RTP timestamp according to the local clock */
            uint32_t expected_ts = ((now - context->a_start_time)*akhz) / 1000 + context->a_start_ts;
            /* Evaluate current delay */
            int32_t delay_now = context->a_last_ts - expected_ts;
            /* Exponentially weighted moving average estimation */
            int32_t delay_estimate = (63 * context->a_prev_delay + delay_now) / 64;
            /* Save previous delay for the next iteration*/
            context->a_prev_delay = delay_estimate;
            /* Evaluate the distance between active delay and current delay estimate */
            int32_t offset = context->a_active_delay - delay_estimate;
            LLOG(LL_TRACE, "audio skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16,
                 context->a_last_ssrc, context->a_last_ts, expected_ts, offset, context->a_ts_offset, context->a_seq_offset);
            int32_t skew_th = RTP_AUDIO_SKEW_TH_MS * akhz;
            /* Evaluation phase */
            if (context->a_evaluating_start_time > 0) {
                /* Check if the offset has surpassed half the threshold during the evaluating phase */
                if (now - context->a_evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS / 2 * ZL_USEC_PER_SEC) {
                    if (abs(offset) <= skew_th / 2) {
                        LLOG(LL_TRACE, "audio skew SSRC=%"SCNu32" evaluation phase continue", context->a_last_ssrc);
                    } else {
                        LLOG(LL_TRACE, "audio skew SSRC=%"SCNu32" evaluation phase reset", context->a_last_ssrc);
                        context->a_start_time = now;
                        context->a_evaluating_start_time = now;
                        context->a_start_ts = context->a_last_ts;
                    }
                } else {
                    LLOG(LL_TRACE, "audio skew SSRC=%"SCNu32" evaluation phase stop", context->a_last_ssrc);
                    context->a_evaluating_start_time = 0;
                }
                return 0;
            }
            /* Check if the offset has surpassed the threshold */
            if (offset >= skew_th) {
                /* The source is slowing down */
                /* Update active delay */
                context->a_active_delay = delay_estimate;
                /* Adjust ts offset */
                context->a_ts_offset += skew_th;
                /* Calculate last ts increase */
                uint32_t ts_incr = context->a_last_ts - context->a_prev_ts;
                /* Evaluate sequence number jump */
                uint16_t jump = (skew_th + ts_incr - 1) / ts_incr;
                /* Adjust seq num offset */
                context->a_seq_offset += jump;
                exit_status = jump;
            } else if (offset <= -skew_th) {
                /* The source is speeding up*/
                /* Update active delay */
                context->a_active_delay = delay_estimate;
                /* Adjust ts offset */
                context->a_ts_offset -= skew_th;
                /* Set target ts */
                context->a_target_ts = context->a_last_ts + skew_th;
                if (context->a_target_ts == 0)
                    context->a_target_ts = 1;
                /* Adjust seq num offset */
                context->a_seq_offset--;
                exit_status = -1;
            }
        }
    }

    /* Skew compensation */
    /* Fix header timestamp considering the active offset */
    uint32_t fixed_rtp_ts = context->a_last_ts + context->a_ts_offset;
    header->timestamp = htonl(fixed_rtp_ts);
    /* Fix header sequence number considering the total offset */
    uint16_t fixed_rtp_seq = context->a_last_seq + context->a_seq_offset;
    header->seq_number = htons(fixed_rtp_seq);

    return exit_status;
}

int rtz_rtp_skew_compensate_video(rtp_header *header, rtz_rtp_switching_context *context, int64_t now)
{
    /* Reset values if a new ssrc has been detected */
    if (context->v_new_ssrc) {
        LLOG(LL_TRACE, "video skew SSRC=%"SCNu32" resetting status\n", context->v_last_ssrc);
        context->v_reference_time = now;
        context->v_start_time = 0;
        context->v_evaluating_start_time = 0;
        context->v_start_ts = 0;
        context->v_active_delay = 0;
        context->v_prev_delay = 0;
        context->v_seq_offset = 0;
        context->v_ts_offset = 0;
        context->v_target_ts = 0;
        context->v_new_ssrc = 0;
    }

    /* N 	: a N sequence numbers jump has been performed */
    /* 0  	: any new skew compensation has been applied */
    /* -N  	: a N packets drop must be performed */
    int exit_status = 0;

    /* Do not execute skew analysis in the first seconds */
    if (now - context->v_reference_time < SKEW_DETECTION_WAIT_TIME_SECS / 2 * ZL_USEC_PER_SEC) {
        return 0;
    } else if (!context->v_start_time) {
        LLOG(LL_TRACE, "video skew SSRC=%"SCNu32" evaluation phase start", context->v_last_ssrc);
        context->v_start_time = now;
        context->v_evaluating_start_time = now;
        context->v_start_ts = context->v_last_ts;
    }

    /* Skew analysis */
    /* Are we waiting for a target timestamp? (a negative skew has been evaluated in a previous iteration) */
    if (context->v_target_ts > 0 && (int32_t)(context->v_target_ts - context->v_last_ts) > 0) {
        context->v_seq_offset--;
        exit_status = -1;
    } else {
        context->v_target_ts = 0;
        /* Do not execute analysis for out of order packets or multi-packets frame */
        if (context->v_last_seq == context->v_prev_seq + 1 && context->v_last_ts != context->v_prev_ts) {
            /* Set the sample rate */
            uint32_t vkhz = 90; /* 90khz */
            /* Evaluate the local RTP timestamp according to the local clock */
            uint32_t expected_ts = ((now - context->v_start_time)*vkhz) / 1000 + context->v_start_ts;
            /* Evaluate current delay */
            int32_t delay_now = context->v_last_ts - expected_ts;
            /* Exponentially weighted moving average estimation */
            int32_t delay_estimate = (63 * context->v_prev_delay + delay_now) / 64;
            /* Save previous delay for the next iteration*/
            context->v_prev_delay = delay_estimate;
            /* Evaluate the distance between active delay and current delay estimate */
            int32_t offset = context->v_active_delay - delay_estimate;
            LLOG(LL_TRACE, "video skew status SSRC=%"SCNu32" RECVD_TS=%"SCNu32" EXPTD_TS=%"SCNu32" OFFSET=%"SCNi32" TS_OFFSET=%"SCNi32" SEQ_OFFSET=%"SCNi16,
                 context->v_last_ssrc, context->v_last_ts, expected_ts, offset, context->v_ts_offset, context->v_seq_offset);
            int32_t skew_th = RTP_VIDEO_SKEW_TH_MS * vkhz;
            /* Evaluation phase */
            if (context->v_evaluating_start_time > 0) {
                /* Check if the offset has surpassed half the threshold during the evaluating phase */
                if (now - context->v_evaluating_start_time <= SKEW_DETECTION_WAIT_TIME_SECS / 2 * ZL_USEC_PER_SEC) {
                    if (abs(offset) <= skew_th / 2) {
                        LLOG(LL_TRACE, "video skew SSRC=%"SCNu32" evaluation phase continue", context->v_last_ssrc);
                    } else {
                        LLOG(LL_TRACE, "video skew SSRC=%"SCNu32" evaluation phase reset", context->v_last_ssrc);
                        context->v_start_time = now;
                        context->v_evaluating_start_time = now;
                        context->v_start_ts = context->v_last_ts;
                    }
                } else {
                    LLOG(LL_TRACE, "video skew SSRC=%"SCNu32" evaluation phase stop", context->v_last_ssrc);
                    context->v_evaluating_start_time = 0;
                }
                return 0;
            }
            /* Check if the offset has surpassed the threshold */
            if (offset >= skew_th) {
                /* The source is slowing down */
                /* Update active delay */
                context->v_active_delay = delay_estimate;
                /* Adjust ts offset */
                context->v_ts_offset += skew_th;
                /* Calculate last ts increase */
                uint32_t ts_incr = context->v_last_ts - context->v_prev_ts;
                /* Evaluate sequence number jump */
                uint16_t jump = (skew_th + ts_incr - 1) / ts_incr;
                /* Adjust seq num offset */
                context->v_seq_offset += jump;
                exit_status = jump;
            } else if (offset <= -skew_th) {
                /* The source is speeding up*/
                /* Update active delay */
                context->v_active_delay = delay_estimate;
                /* Adjust ts offset */
                context->v_ts_offset -= skew_th;
                /* Set target ts */
                context->v_target_ts = context->v_last_ts + skew_th;
                if (context->v_target_ts == 0)
                    context->v_target_ts = 1;
                /* Adjust seq num offset */
                context->v_seq_offset--;
                exit_status = -1;
            }
        }
    }

    /* Skew compensation */
    /* Fix header timestamp considering the active offset */
    uint32_t fixed_rtp_ts = context->v_last_ts + context->v_ts_offset;
    header->timestamp = htonl(fixed_rtp_ts);
    /* Fix header sequence number considering the total offset */
    uint16_t fixed_rtp_seq = context->v_last_seq + context->v_seq_offset;
    header->seq_number = htons(fixed_rtp_seq);

    return exit_status;
}

void rtz_rtp_header_update(rtp_header *header, rtz_rtp_switching_context *context, int video, int step)
{
    if (header == NULL || context == NULL)
        return;
    /* Note: while the step property is still there for compatibility reasons, to
     * keep the signature as it was before, it's ignored: whenever there's a switch
     * to take into account, we compute how much time passed between the last RTP
     * packet with the old SSRC and this new one, and prepare a timestamp accordingly */
    uint32_t ssrc = ntohl(header->ssrc);
    uint32_t timestamp = ntohl(header->timestamp);
    uint16_t seq = ntohs(header->seq_number);
    if (video) {
        if (ssrc != context->v_last_ssrc) {
            /* Video SSRC changed: update both sequence number and timestamp */
            LLOG(LL_TRACE, "Video SSRC changed, %"SCNu32" --> %"SCNu32,
                 context->v_last_ssrc, ssrc);
            context->v_last_ssrc = ssrc;
            context->v_base_ts_prev = context->v_last_ts;
            context->v_base_ts = timestamp;
            context->v_base_seq_prev = context->v_last_seq;
            context->v_base_seq = seq;
            /* How much time since the last video RTP packet? We compute an offset accordingly */
            if (context->v_last_time > 0) {
                int64_t time_diff = zl_hrtimestamp() - context->v_last_time;
                time_diff = (time_diff * 90) / 1000; 	/* We're assuming 90khz here */
                if (time_diff == 0)
                    time_diff = 1;
                context->v_base_ts_prev += (uint32_t)time_diff;
                context->v_last_ts += (uint32_t)time_diff;
                LLOG(LL_TRACE, "Computed offset for video RTP timestamp: %"SCNu32, (uint32_t)time_diff);
            }
            /* Reset skew compensation data */
            context->v_new_ssrc = 1;
        }
        if (context->v_seq_reset) {
            /* Video sequence number was paused for a while: just update that */
            context->v_seq_reset = 0;
            context->v_base_seq_prev = context->v_last_seq;
            context->v_base_seq = seq;
        }
        /* Compute a coherent timestamp and sequence number */
        context->v_prev_ts = context->v_last_ts;
        context->v_last_ts = (timestamp - context->v_base_ts) + context->v_base_ts_prev;
        context->v_prev_seq = context->v_last_seq;
        context->v_last_seq = (seq - context->v_base_seq) + context->v_base_seq_prev + 1;
        /* Update the timestamp and sequence number in the RTP packet */
        header->timestamp = htonl(context->v_last_ts);
        header->seq_number = htons(context->v_last_seq);
        /* Take note of when we last handled this RTP packet */
        context->v_last_time = zl_hrtimestamp();
    } else {
        if (ssrc != context->a_last_ssrc) {
            /* Audio SSRC changed: update both sequence number and timestamp */
            LLOG(LL_TRACE, "Audio SSRC changed, %"SCNu32" --> %"SCNu32,
                 context->a_last_ssrc, ssrc);
            context->a_last_ssrc = ssrc;
            context->a_base_ts_prev = context->a_last_ts;
            context->a_base_ts = timestamp;
            context->a_base_seq_prev = context->a_last_seq;
            context->a_base_seq = seq;
            /* How much time since the last audio RTP packet? We compute an offset accordingly */
            if (context->a_last_time > 0) {
                int64_t time_diff = zl_hrtimestamp() - context->a_last_time;
                int akhz = 48;
                if (header->type == 0 || header->type == 8 || header->type == 9)
                    akhz = 8;	/* We're assuming 48khz here (Opus), unless it's G.711/G.722 (8khz) */
                time_diff = (time_diff*akhz) / 1000;
                if (time_diff == 0)
                    time_diff = 1;
                context->a_base_ts_prev += (uint32_t)time_diff;
                context->a_prev_ts += (uint32_t)time_diff;
                context->a_last_ts += (uint32_t)time_diff;
                LLOG(LL_TRACE, "Computed offset for audio RTP timestamp: %"SCNu32, (uint32_t)time_diff);
            }
            /* Reset skew compensation data */
            context->a_new_ssrc = 1;
        }
        if (context->a_seq_reset) {
            /* Audio sequence number was paused for a while: just update that */
            context->a_seq_reset = 0;
            context->a_base_seq_prev = context->a_last_seq;
            context->a_base_seq = seq;
        }
        /* Compute a coherent timestamp and sequence number */
        context->a_prev_ts = context->a_last_ts;
        context->a_last_ts = (timestamp - context->a_base_ts) + context->a_base_ts_prev;
        context->a_prev_seq = context->a_last_seq;
        context->a_last_seq = (seq - context->a_base_seq) + context->a_base_seq_prev + 1;
        /* Update the timestamp and sequence number in the RTP packet */
        header->timestamp = htonl(context->a_last_ts);
        header->seq_number = htons(context->a_last_seq);
        /* Take note of when we last handled this RTP packet */
        context->a_last_time = zl_hrtimestamp();
    }
}


/* SRTP stuff: we may need our own randomizer */
int srtp_crypto_get_random(uint8_t *key, int len)
{
    /* libsrtp 2.0 doesn't have crypto_get_random, we use OpenSSL's RAND_* to replace it:
     * 		https://wiki.openssl.org/index.php/Random_Numbers */
    int rc = RAND_bytes(key, len);
    if (rc != 1) {
        /* Error generating */
        return -1;
    }
    return 0;
}

/* SRTP error codes as a string array */
static const char *rtz_srtp_error[] =
{
    "srtp_err_status_ok",
    "srtp_err_status_fail",
    "srtp_err_status_bad_param",
    "srtp_err_status_alloc_fail",
    "srtp_err_status_dealloc_fail",
    "srtp_err_status_init_fail",
    "srtp_err_status_terminus",
    "srtp_err_status_auth_fail",
    "srtp_err_status_cipher_fail",
    "srtp_err_status_replay_fail",
    "srtp_err_status_replay_old",
    "srtp_err_status_algo_fail",
    "srtp_err_status_no_such_op",
    "srtp_err_status_no_ctx",
    "srtp_err_status_cant_check",
    "srtp_err_status_key_expired",
    "srtp_err_status_socket_err",
    "srtp_err_status_signal_err",
    "srtp_err_status_nonce_bad",
    "srtp_err_status_read_fail",
    "srtp_err_status_write_fail",
    "srtp_err_status_parse_err",
    "srtp_err_status_encode_err",
    "srtp_err_status_semaphore_err",
    "srtp_err_status_pfkey_err",
};
const char *rtz_srtp_error_str(int error)
{
    if (error < 0 || error > 24)
        return NULL;
    return rtz_srtp_error[error];
}

/* Payload types we'll offer internally */
#define OPUS_PT		111
#define ISAC32_PT	104
#define ISAC16_PT	103
#define PCMU_PT		0
#define PCMA_PT		8
#define G722_PT		9
#define VP8_PT		96
#define VP9_PT		101
#define H264_PT		107
const char *rtz_audiocodec_name(rtz_audiocodec acodec)
{
    switch (acodec) {
    case RTZ_AUDIOCODEC_NONE:
        return "none";
    case RTZ_AUDIOCODEC_OPUS:
        return "opus";
    case RTZ_AUDIOCODEC_PCMU:
        return "pcmu";
    case RTZ_AUDIOCODEC_PCMA:
        return "pcma";
    case RTZ_AUDIOCODEC_G722:
        return "g722";
    case RTZ_AUDIOCODEC_ISAC_32K:
        return "isac32";
    case RTZ_AUDIOCODEC_ISAC_16K:
        return "isac16";
    default:
        /* Shouldn't happen */
        return "opus";
    }
}
rtz_audiocodec rtz_audiocodec_from_name(const char *name)
{
    if (name == NULL)
        return RTZ_AUDIOCODEC_NONE;
    else if (!strcasecmp(name, "opus"))
        return RTZ_AUDIOCODEC_OPUS;
    else if (!strcasecmp(name, "isac32"))
        return RTZ_AUDIOCODEC_ISAC_32K;
    else if (!strcasecmp(name, "isac16"))
        return RTZ_AUDIOCODEC_ISAC_16K;
    else if (!strcasecmp(name, "pcmu"))
        return RTZ_AUDIOCODEC_PCMU;
    else if (!strcasecmp(name, "pcma"))
        return RTZ_AUDIOCODEC_PCMA;
    else if (!strcasecmp(name, "g722"))
        return RTZ_AUDIOCODEC_G722;
    LLOG(LL_WARN, "Unsupported audio codec '%s'", name);
    return RTZ_AUDIOCODEC_NONE;
}
int rtz_audiocodec_pt(rtz_audiocodec acodec)
{
    switch (acodec) {
    case RTZ_AUDIOCODEC_NONE:
        return -1;
    case RTZ_AUDIOCODEC_OPUS:
        return OPUS_PT;
    case RTZ_AUDIOCODEC_ISAC_32K:
        return ISAC32_PT;
    case RTZ_AUDIOCODEC_ISAC_16K:
        return ISAC16_PT;
    case RTZ_AUDIOCODEC_PCMU:
        return PCMU_PT;
    case RTZ_AUDIOCODEC_PCMA:
        return PCMA_PT;
    case RTZ_AUDIOCODEC_G722:
        return G722_PT;
    default:
        /* Shouldn't happen */
        return OPUS_PT;
    }
}

const char *rtz_videocodec_name(rtz_videocodec vcodec)
{
    switch (vcodec) {
    case RTZ_VIDEOCODEC_NONE:
        return "none";
    case RTZ_VIDEOCODEC_VP8:
        return "vp8";
    case RTZ_VIDEOCODEC_VP9:
        return "vp9";
    case RTZ_VIDEOCODEC_H264:
        return "h264";
    default:
        /* Shouldn't happen */
        return "vp8";
    }
}
rtz_videocodec rtz_videocodec_from_name(const char *name)
{
    if (name == NULL)
        return RTZ_VIDEOCODEC_NONE;
    else if (!strcasecmp(name, "vp8"))
        return RTZ_VIDEOCODEC_VP8;
    else if (!strcasecmp(name, "vp9"))
        return RTZ_VIDEOCODEC_VP9;
    else if (!strcasecmp(name, "h264"))
        return RTZ_VIDEOCODEC_H264;
    LLOG(LL_WARN, "Unsupported video codec '%s'", name);
    return RTZ_VIDEOCODEC_NONE;
}
int rtz_videocodec_pt(rtz_videocodec vcodec)
{
    switch (vcodec) {
    case RTZ_VIDEOCODEC_NONE:
        return -1;
    case RTZ_VIDEOCODEC_VP8:
        return VP8_PT;
    case RTZ_VIDEOCODEC_VP9:
        return VP9_PT;
    case RTZ_VIDEOCODEC_H264:
        return H264_PT;
    default:
        /* Shouldn't happen */
        return VP8_PT;
    }
}

void rtz_rtp_simulcasting_context_reset(rtz_rtp_simulcasting_context *context)
{
    if (context == NULL)
        return;
    /* Reset the context values */
    memset(context, 0, sizeof(*context));
    context->substream = -1;
    context->templayer = -1;
}

int rtz_rtp_simulcasting_context_process_rtp(rtz_rtp_simulcasting_context *context,
                                             char *buf, int len, uint32_t *ssrcs, rtz_videocodec vcodec, rtz_rtp_switching_context *sc)
{
    if (!context || !buf || len < 1)
        return 0;
    rtp_header *header = (rtp_header *)buf;
    uint32_t ssrc = ntohl(header->ssrc);
    /* Reset the flags */
    context->changed_substream = 0;
    context->changed_temporal = 0;
    context->need_pli = 0;
    /* Access the packet payload */
    int plen = 0;
    char *payload = rtp_payload(buf, len, &plen);
    if (payload == NULL)
        return 0;
    if (context->substream != context->substream_target) {
        /* There has been a change: let's wait for a keyframe on the target */
        int step = (context->substream < 1 && context->substream_target == 2);
    }
    /* If we haven't received our desired substream yet, let's drop temporarily */
    if (context->last_relayed == 0) {
        /* Let's start slow */
        context->last_relayed = zl_hrtimestamp();
    } else {
        /* Check if 250ms went by with no packet relayed */
        int64_t now = zl_hrtimestamp();
        if (now - context->last_relayed >= 250000) {
            context->last_relayed = now;
            int substream = context->substream - 1;
            if (substream < 0)
                substream = 0;
            if (context->substream != substream) {
                LLOG(LL_WARN, "No packet received on substream %d for a while, falling back to %d",
                     context->substream, substream);
                context->substream = substream;
                /* Notify the caller that we need a PLI */
                context->need_pli = 1;
                /* Notify the caller that the substream changed as well */
                context->changed_substream = 1;
            }
        }
    }
    /* Do we need to drop this? */
    if (ssrc != *(ssrcs + context->substream)) {
        LLOG(LL_TRACE, "Dropping packet (it's from SSRC %"SCNu32", but we're only relaying SSRC %"SCNu32" now",
             ssrc, *(ssrcs + context->substream));
        return 0;
    }
    context->last_relayed = zl_hrtimestamp();
    return 1;
}
