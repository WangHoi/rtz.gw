#pragma once
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>

#define RTP_HEADER_SIZE	12

/** RTP Header (http://tools.ietf.org/html/rfc3550#section-5.1) */
typedef struct rtp_header
{
	uint16_t csrccount:4;
	uint16_t extension:1;
	uint16_t padding:1;
	uint16_t version:2;
	uint16_t type:7;
	uint16_t markerbit:1;
	uint16_t seq_number;
	uint32_t timestamp;
	uint32_t ssrc;
	uint32_t csrc[16];
} rtp_header;

/** RTP packet */
typedef struct rtp_packet {
	char *data;
	int length;
	int64_t created;
	int64_t last_retransmit;
} rtp_packet;

/** RTP extension */
typedef struct rtp_header_extension {
	uint16_t type;
	uint16_t length;
} rtp_header_extension;

/** a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level */
#define RTZ_RTP_EXTMAP_AUDIO_LEVEL		"urn:ietf:params:rtp-hdrext:ssrc-audio-level"
/** a=extmap:2 urn:ietf:params:rtp-hdrext:toffset */
#define RTZ_RTP_EXTMAP_TOFFSET			"urn:ietf:params:rtp-hdrext:toffset"
/** a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time */
#define RTZ_RTP_EXTMAP_ABS_SEND_TIME		"http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
/** a=extmap:4 urn:3gpp:video-orientation */
#define RTZ_RTP_EXTMAP_VIDEO_ORIENTATION	"urn:3gpp:video-orientation"
/** a=extmap:5 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01 */
#define RTZ_RTP_EXTMAP_TRANSPORT_WIDE_CC	"http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
/** a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay */
#define RTZ_RTP_EXTMAP_PLAYOUT_DELAY		"http://www.webrtc.org/experiments/rtp-hdrext/playout-delay"
/** a=extmap:3/sendonly urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id */
#define RTZ_RTP_EXTMAP_RTP_STREAM_ID		"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"

/** Helper to quickly access the RTP payload, skipping header and extensions
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[out] plen The payload data length in bytes
 * @returns A pointer to where the payload data starts, or NULL otherwise; plen is also set accordingly */
char *rtp_payload(char *buf, int len, int *plen);

/** Helper to quickly find the extension data
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The 'a=extmap:' id
 * @param[out] byte The one byte extension value, NULL to ignore
 * @param[out] word The four bytes extension value, NULL to ignore
 * @param[out] ref The pointer to extension value, , NULL to ignore
 * @return 0 if found, -1 otherwise. */
int rtp_header_extension_find(char *buf, int len, int id,
                              uint8_t *byte, uint32_t *word, char **playout_delay_ext_ref);

/** Ugly and dirty helper to quickly get the id associated with an RTP extension (extmap) in an SDP
 * @param sdp The SDP to parse
 * @param extension The extension namespace to look for
 * @returns The extension id, if found, -1 otherwise */
int rtp_header_extension_get_id(const char *sdp, const char *extension);

/** Ugly and dirty helper to quickly get the RTP extension namespace associated with an id (extmap) in an SDP
 * @note This only looks for the extensions we know about, those defined in rtp.h
 * @param sdp The SDP to parse
 * @param id The extension id to look for
 * @returns The extension namespace, if found, NULL otherwise */
const char *rtp_header_extension_get_from_id(const char *sdp, int id);

/** Helper to parse a ssrc-audio-level RTP extension (https://tools.ietf.org/html/rfc6464)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] level The level value in dBov (0=max, 127=min)
 * @returns 0 if found, -1 otherwise */
int rtp_header_extension_parse_audio_level(char *buf, int len, int id, int *level);

/** Helper to parse a video-orientation RTP extension (http://www.3gpp.org/ftp/Specs/html-info/26114.htm)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] c The value of the Camera (C) bit
 * @param[out] f The value of the Flip (F) bit
 * @param[out] r1 The value of the first Rotation (R1) bit
 * @param[out] r0 The value of the second Rotation (R0) bit
 * @returns 0 if found, -1 otherwise */
int rtp_header_extension_parse_video_orientation(char *buf, int len, int id,
	int *c, int *f, int *r1, int *r0);

/** Helper to parse a playout-delay RTP extension (https://webrtc.org/experiments/rtp-hdrext/playout-delay)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] min_delay The minimum delay value
 * @param[out] max_delay The maximum delay value
 * @returns 0 if found, -1 otherwise */
int rtp_header_extension_parse_playout_delay(char *buf, int len, int id,
	uint16_t *min_delay, uint16_t *max_delay);

/** Helper to parse a rtp-stream-id RTP extension (https://tools.ietf.org/html/draft-ietf-avtext-rid-09)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] sdes_item Buffer where the RTP stream ID will be written
 * @param[in] sdes_len Size of the input/output buffer
 * @returns 0 if found, -1 otherwise */
int rtp_header_extension_parse_rtp_stream_id(char *buf, int len, int id,
	char *sdes_item, int sdes_len);

/** Helper to parse a rtp-stream-id RTP extension (https://tools.ietf.org/html/draft-ietf-avtext-rid-09)
 * @param[in] buf The packet data
 * @param[in] len The packet data length in bytes
 * @param[in] id The extension ID to look for
 * @param[out] transSeqNum transport wide sequence number
 * @returns 0 if found, -1 otherwise */
int rtp_header_extension_parse_transport_wide_cc(char *buf, int len, int id,
	uint16_t *transSeqNum);

/** RTP context, in order to make sure SSRC changes result in coherent seq/ts increases */
typedef struct rtz_rtp_switching_context {
	uint32_t a_last_ssrc, a_last_ts, a_base_ts, a_base_ts_prev, a_prev_ts, a_target_ts, a_start_ts,
			v_last_ssrc, v_last_ts, v_base_ts, v_base_ts_prev, v_prev_ts, v_target_ts, v_start_ts;
	uint16_t a_last_seq, a_prev_seq, a_base_seq, a_base_seq_prev,
			v_last_seq, v_prev_seq, v_base_seq, v_base_seq_prev;
	int a_seq_reset, a_new_ssrc,
			v_seq_reset, v_new_ssrc;
	int16_t a_seq_offset,
			v_seq_offset;
	int32_t a_prev_delay, a_active_delay, a_ts_offset,
			v_prev_delay, v_active_delay, v_ts_offset;
	int64_t a_last_time, a_reference_time, a_start_time, a_evaluating_start_time,
			v_last_time, v_reference_time, v_start_time, v_evaluating_start_time;
} rtz_rtp_switching_context;

/** Set (or reset) the context fields to their default values
 * @param[in] context The context to (re)set */
void rtz_rtp_switching_context_reset(rtz_rtp_switching_context *context);

/** Use the context info to update the RTP header of a packet, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] video Whether this is an audio or a video packet
 * @param[in] step \b deprecated The expected timestamp step */
void rtz_rtp_header_update(rtp_header *header, rtz_rtp_switching_context *context, int video, int step);

#define RTP_AUDIO_SKEW_TH_MS 120
#define RTP_VIDEO_SKEW_TH_MS 120
#define SKEW_DETECTION_WAIT_TIME_SECS 10

/** Use the context info to compensate for audio source skew, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] now \b The packet arrival monotonic time
 * @returns 0 if no compensation is needed, -N if a N packets drop must be performed, N if a N sequence numbers jump has been performed */
int rtz_rtp_skew_compensate_audio(rtp_header *header, rtz_rtp_switching_context *context, int64_t now);
/** Use the context info to compensate for video source skew, if needed
 * @param[in] header The RTP header to update
 * @param[in] context The context to use as a reference
 * @param[in] now \b The packet arrival monotonic time
 * @returns 0 if no compensation is needed, -N if a N packets drop must be performed, N if a N sequence numbers jump has been performed */
int rtz_rtp_skew_compensate_video(rtp_header *header, rtz_rtp_switching_context *context, int64_t now);

typedef enum rtz_audiocodec {
	RTZ_AUDIOCODEC_NONE,
	RTZ_AUDIOCODEC_OPUS,
	RTZ_AUDIOCODEC_PCMU,
	RTZ_AUDIOCODEC_PCMA,
	RTZ_AUDIOCODEC_G722,
	RTZ_AUDIOCODEC_ISAC_32K,
	RTZ_AUDIOCODEC_ISAC_16K
} rtz_audiocodec;
const char *rtz_audiocodec_name(rtz_audiocodec acodec);
rtz_audiocodec rtz_audiocodec_from_name(const char *name);
int rtz_audiocodec_pt(rtz_audiocodec acodec);

typedef enum rtz_videocodec {
	RTZ_VIDEOCODEC_NONE,
	RTZ_VIDEOCODEC_VP8,
	RTZ_VIDEOCODEC_VP9,
	RTZ_VIDEOCODEC_H264
} rtz_videocodec;
const char *rtz_videocodec_name(rtz_videocodec vcodec);
rtz_videocodec rtz_videocodec_from_name(const char *name);
int rtz_videocodec_pt(rtz_videocodec vcodec);


/** Helper struct for processing and tracking simulcast streams */
typedef struct rtz_rtp_simulcasting_context {
	/** Which simulcast substream we should forward back */
	int substream;
	/** As above, but to handle transitions (e.g., wait for keyframe, or get this if available) */
	int substream_target;
	/** Which simulcast temporal layer we should forward back */
	int templayer;
	/** As above, but to handle transitions (e.g., wait for keyframe) */
	int templayer_target;
	/** When we relayed the last packet (used to detect when substreams become unavailable) */
	int64_t last_relayed;
	/** Whether the substream has changed after processing a packet */
	int changed_substream;
	/** Whether the temporal layer has changed after processing a packet */
	int changed_temporal;
	/** Whether we need to send the user a keyframe request (PLI) */
	int need_pli;
} rtz_rtp_simulcasting_context;

/** Set (or reset) the context fields to their default values
 * @param[in] context The context to (re)set */
void rtz_rtp_simulcasting_context_reset(rtz_rtp_simulcasting_context *context);

/** Process an RTP packet, and decide whether this should be relayed or not, updating the context accordingly
 * \note Calling this method resets the \c changed_substream , \c changed_temporal and \c need_pli
 * properties, and updates them according to the decisions made after processinf the packet
 * @param[in] context The simulcasting context to use
 * @param[in] buf The RTP packet to process
 * @param[in] len The length of the RTP packet (header, extension and payload)
 * @param[in] ssrcs The simulcast SSRCs to refer to
 * @param[in] vcodec Video codec of the RTP payload
 * @param[in] sc RTP switching context to refer to, if any (only needed for VP8 and dropping temporal layers)
 * @returns TRUE if the packet should be relayed, FALSE if it should be dropped instead */
int rtz_rtp_simulcasting_context_process_rtp(rtz_rtp_simulcasting_context *context,
	char *buf, int len, uint32_t *ssrcs, rtz_videocodec vcodec, rtz_rtp_switching_context *sc);
