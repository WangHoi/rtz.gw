#include "ice.h"
#include "sbuf.h"
#include "event_loop.h"
#include "tcp_chan.h"
#include "net_util.h"
#include "log.h"
#include "list.h"
#include "stun.h"
#include "dtls.h"
#include "rtp_srtp.h"
#include "rtcp.h"
#include "rtp.h"
#include "rtz_server.h"
#include "rtz_shard.h"
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cJSON.h>
#include <assert.h>

enum ice_candidate_state {
    ICE_CAND_STATE_EMPTY,
    ICE_CAND_STATE_VALID,
    ICE_CAND_STATE_NOMINATED,
};

enum ice_candidate_type {
    ICE_CAND_TYPE_HOST,
    ICE_CAND_TYPE_PRFLX,
    ICE_CAND_TYPE_SRFLX,
    ICE_CAND_TYPE_RELAY,
};

enum {
    ICE_UFRAG_LENGTH = 4,
    ICE_PWD_LENGTH = 22,
    ICE_MAX_LOCAL_PREFERENCE = 65535,
    ICE_MAX_USERNAME_LENGTH = 32,
    ICE_MAX_TCP_FRAME_SIZE = 1500,
    ICE_MAX_TCP_WRITE_BUF_SIZE = 2 << 20,

    MAX_PER_SEND_SIZE = 32 * 1024,
    DSCP_CLASS_EF = 0b101110,
    DROP_THREHOLD = 128 * 1024,
};

#define ICE_PACKET_AUDIO_RTP    0
#define ICE_PACKET_VIDEO_RTP	1
//#define ICE_PACKET_DATA_RTP	    2
#define ICE_PACKET_AUDIO_RTCP   3
#define ICE_PACKET_VIDEO_RTCP	4
//#define ICE_PACKET_DATA_RTCP	5
#define ICE_PACKET_DTLS         6
#define ICE_PACKET_STUN         7

/* Enqueued (S)RTP/(S)RTCP packet to send */
typedef struct ice_queued_packet_t {
    char *data;
    int length;
    int type;
    int retransmission;
    int encrypted;
    int64_t added;
    struct list_head link;
} ice_queued_packet_t;

/** Media statistics
 * @note To improve with more stuff */
typedef struct ice_stats_info_t {
    /** Packets sent or received */
    uint32_t packets;
    /** Bytes sent or received */
    uint64_t bytes;
    /** Bytes sent or received in the last second */
    uint32_t bytes_lastsec, bytes_lastsec_temp;
    /** Time we last updated the last second counter */
    int64_t updated;
    /** Whether or not we notified about lastsec issues already */
    int notified_lastsec;
    /** Number of NACKs sent or received */
    uint32_t nacks;
} ice_stats_info_t;

/** Media statistics container
 * @note To improve with more stuff */
typedef struct ice_stats {
    /** Audio info */
    ice_stats_info_t audio;
    /** Video info (considering we may be simulcasting) */
    ice_stats_info_t video;
    /** Last time the slow_link callback (of the plugin) was called */
    int64_t last_slowlink_time;
    /** Start time of recent NACKs (for slow_link) */
    int64_t sl_nack_period_ts;
    /** Count of recent NACKs (for slow_link) */
    unsigned sl_nack_recent_cnt;
} ice_stats;

struct ice_server_t {
    zl_loop_t *loop;
    sbuf_t *ip;
    unsigned short port;
    tcp_srv_t *tcp_srv;
    struct list_head agent_list;
};

struct ice_component_t {
    ice_stream_t *stream;
    /** Monotonic time of when this component has successfully connected */
    long long component_connected;
    /** DTLS-SRTP stack */
    struct dtls_srtp *dtls;
    /** Stats for incoming data (audio/video/data) */
    ice_stats in_stats;
    /** Stats for outgoing data (audio/video/data) */
    ice_stats out_stats;
};

struct ice_stream_t {
    ice_agent_t *agent;
    /** Audio SSRC of the server for this stream */
    uint32_t audio_ssrc;
    /** Audio seqno */
    uint16_t audio_seqno;
    /** Video SSRC of the server for this stream */
    uint32_t video_ssrc;
    /** Video seqno */
    uint16_t video_seqno;
    /** Codecs used by this stream */
    sbuf_t *audio_codec, *video_codec;
    /** RTCP context for the audio stream */
    struct rtcp_context *audio_rtcp_ctx;
    /** RTCP context for the video stream */
    struct rtcp_context *video_rtcp_ctx;
    /** First received audio NTP timestamp */
    int64_t audio_first_ntp_ts;
    /** First received audio RTP timestamp */
    uint32_t audio_first_rtp_ts;
    /** First received video NTP timestamp */
    int64_t video_first_ntp_ts;
    /** First received video NTP RTP timestamp */
    uint32_t video_first_rtp_ts;
    /** Last sent audio RTP timestamp */
    uint32_t audio_last_ts;
    /** Last sent video RTP timestamp */
    uint32_t video_last_ts;
    /** The ICE username for local stream */
    sbuf_t *luser;
    /** The ICE password for local stream */
    sbuf_t *lpass;
    /** Hashing algorithm used by the peer for the DTLS certificate (e.g., "SHA-256") */
    sbuf_t *remote_hashing;
    /** Hashed fingerprint of the peer's certificate, as parsed in SDP */
    sbuf_t *remote_fingerprint;
    /** The ICE username for remote stream */
    sbuf_t *ruser;
    /** The ICE password for remote stream */
    sbuf_t *rpass;
    /** ICE component */
    ice_component_t *component;
};

struct ice_agent_t {
    ice_server_t *srv;
    void *rtz_handle;
    unsigned flags;
    ice_stream_t *stream;
    sbuf_t *hangup_reason;
    int rtcp_timer;

    struct sockaddr_storage peer_addr;
    tcp_chan_t *peer_tcp;
    struct list_head pkt_list;          /* only RTP,RTCP */

    int cand_state;
    int no_errlog;  /* Suppress error log */
    struct list_head link;
};

struct ice_tcp_chan_udata {
    ice_server_t *srv;
    ice_agent_t *agent;
};

static ice_stream_t *ice_stream_new(ice_agent_t *handle);
static void ice_stream_del(ice_stream_t *stream);
static ice_component_t *ice_component_new(ice_stream_t *stream);
static void ice_component_del(ice_component_t *component);
static uint32_t get_priority(enum ice_candidate_type type, int local_preference, int component);
static void stun_handler(ice_server_t *srv, const void *data, int size,
                         const struct sockaddr *addr, socklen_t addrlen,
                         tcp_chan_t *tcp_chan);
static void dtls_handler(ice_agent_t *agent, const void *data, int size,
                         const struct sockaddr *addr, socklen_t addrlen);
static void srtcp_handler(ice_agent_t *agent, const void *data, int size);
static void srtp_handler(ice_agent_t *agent, const void *data, int size);
static void rtcp_handler(ice_agent_t *agent, int video, const void *data, int size);
static void rtp_handler(ice_agent_t *agent, int video, const void *data, int size);
static ice_agent_t *find_agent_by_username(ice_server_t *srv, const char *ufrag);
static ice_agent_t *find_agent_by_address(ice_server_t *srv, const struct sockaddr *addr,
                                          socklen_t addrlen, int tcp);
static void ice_free_queued_packet(ice_queued_packet_t *pkt);
static void ice_send_packet(ice_agent_t *agent, ice_queued_packet_t *pkt);
static void rtcp_timeout_handler(zl_loop_t *loop, int id, void *udata);
static void ice_tcp_accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata);
static void ice_tcp_data_handler(tcp_chan_t *chan, void *udata);
static void ice_tcp_sent_handler(tcp_chan_t *chan, void *udata);
static void ice_tcp_error_handler(tcp_chan_t *chan, int status, void *udata);
static void ice_tcp_error_cleanup(tcp_chan_t *chan, struct ice_tcp_chan_udata *udata);

static void ice_send(ice_agent_t *agent, int type, const void *data, int size);
static void update_stats(ice_component_t *component, ice_queued_packet_t *pkt);

ice_server_t *ice_server_new(zl_loop_t *loop)
{
    ice_server_t *srv = malloc(sizeof(ice_server_t));
    memset(srv, 0, sizeof(ice_server_t));
    srv->loop = loop;
    srv->ip = sbuf_new1(16);
    sbuf_strcpy(srv->ip, "0.0.0.0");
    srv->tcp_srv = tcp_srv_new(loop);
    INIT_LIST_HEAD(&srv->agent_list);
    return srv;
}

void ice_server_del(ice_server_t *srv)
{
    tcp_srv_del(srv->tcp_srv);
    sbuf_del(srv->ip);
    free(srv);
}

void ice_server_bind(ice_server_t *srv, const char *ip, unsigned short port)
{
    sbuf_strcpy(srv->ip, ip);
    srv->port = port;
    tcp_srv_bind(srv->tcp_srv, ip, port);
}

void ice_tcp_accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    ice_server_t *srv = udata;
    struct ice_tcp_chan_udata *chan_udata = malloc(sizeof(struct ice_tcp_chan_udata));
    memset(chan_udata, 0, sizeof(struct ice_tcp_chan_udata));
    chan_udata->srv = srv;
    tcp_chan_set_cb(chan, ice_tcp_data_handler, ice_tcp_sent_handler, ice_tcp_error_handler, chan_udata);
    /* typical minimum buffer size: 4608 */
    set_socket_send_buf_size(tcp_chan_fd(chan), 0/*16384*/);
    int ret = set_ip_tos(tcp_chan_fd(chan), DSCP_CLASS_EF); /* EF class */
    //int size;
    //get_socket_send_buf_size(tcp_chan_fd(chan), &size);
    //LLOG(LL_WARN, "new send buf size=%d", size);
}

void ice_server_start(ice_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, ice_tcp_accept_handler, srv);
    tcp_srv_listen(srv->tcp_srv);
}

ice_agent_t *ice_agent_new(ice_server_t *srv, void *rtz_handle)
{
    ice_agent_t *agent = malloc(sizeof(ice_agent_t));
    memset(agent, 0, sizeof(ice_agent_t));
    agent->srv = srv;
    agent->rtz_handle = rtz_handle;
    agent->hangup_reason = sbuf_new();
    agent->stream = ice_stream_new(agent);
    agent->rtcp_timer = -1;
    list_add(&agent->link, &srv->agent_list);
    INIT_LIST_HEAD(&agent->pkt_list);
    LLOG(LL_TRACE, "create agent %p handle %p luser=%s", agent,
         agent->rtz_handle, agent->stream->luser->data);
    return agent;
}

void ice_agent_del(ice_agent_t *agent)
{
    if (!agent)
        return;
    LLOG(LL_TRACE, "release agent %p handle %p luser='%s'", agent,
         agent->rtz_handle, agent->stream->luser->data);
    if (agent->peer_tcp)
        ice_tcp_error_cleanup(agent->peer_tcp, tcp_chan_get_userdata(agent->peer_tcp));
    ice_webrtc_hangup(agent, "Delete ICE Agent");
    ice_flags_set(agent, ICE_HANDLE_WEBRTC_STOP);
    ice_stream_del(agent->stream);
    sbuf_del(agent->hangup_reason);
    list_del(&agent->link);
    ice_queued_packet_t *pkt, *tmp;
    list_for_each_entry_safe(pkt, tmp, &agent->pkt_list, link) {
        ice_free_queued_packet(pkt);
    }
    free(agent);
}

ice_stream_t *ice_stream_new(ice_agent_t *agent)
{
    ice_stream_t *stream = malloc(sizeof(ice_stream_t));
    memset(stream, 0, sizeof(ice_stream_t));
    stream->agent = agent;
    stream->audio_codec = sbuf_new();
    stream->video_codec = sbuf_new();
    stream->luser = sbuf_random_string(ICE_UFRAG_LENGTH);
    char shard_prefix = 'A';
    int idx = rtz_shard_get_index_ct();
    if (idx >= 0)
        shard_prefix += idx;
    sbuf_prependc(stream->luser, shard_prefix);
    stream->lpass = sbuf_random_string(ICE_PWD_LENGTH);
    stream->remote_hashing = sbuf_new();
    stream->remote_fingerprint = sbuf_new();
    stream->ruser = sbuf_new1(ICE_UFRAG_LENGTH + 1);
    stream->rpass = sbuf_new1(ICE_PWD_LENGTH + 1);
    do {
        stream->audio_ssrc = (uint32_t)lrand48();
    } while (stream->audio_ssrc < 10);
    do {
        stream->video_ssrc = (uint32_t)lrand48();
    } while (stream->video_ssrc < 10);
    stream->audio_rtcp_ctx = malloc(sizeof(rtcp_context));
    memset(stream->audio_rtcp_ctx, 0, sizeof(rtcp_context));
    stream->audio_rtcp_ctx->tb = 8000;
    stream->video_rtcp_ctx = malloc(sizeof(rtcp_context));
    memset(stream->video_rtcp_ctx, 0, sizeof(rtcp_context));
    stream->video_rtcp_ctx->tb = 90000;
    stream->component = ice_component_new(stream);
    return stream;
}

void ice_stream_del(ice_stream_t *stream)
{
    sbuf_del(stream->audio_codec);
    sbuf_del(stream->video_codec);
    sbuf_del(stream->luser);
    sbuf_del(stream->lpass);
    sbuf_del(stream->remote_hashing);
    sbuf_del(stream->remote_fingerprint);
    sbuf_del(stream->ruser);
    sbuf_del(stream->rpass);
    free(stream->audio_rtcp_ctx);
    free(stream->video_rtcp_ctx);
    ice_component_del(stream->component);
    free(stream);
}

ice_component_t *ice_component_new(ice_stream_t *stream)
{
    ice_component_t *component = malloc(sizeof(ice_component_t));
    memset(component, 0, sizeof(ice_component_t));
    component->dtls = dtls_srtp_create(component, DTLS_ROLE_SERVER);
    component->stream = stream;
    return component;
}

void ice_component_del(ice_component_t *component)
{
    dtls_srtp_free(component->dtls);
    free(component);
}

const char *ice_get_luser(ice_agent_t *agent)
{
    return agent->stream->luser->data;
}

const char *ice_get_lpass(ice_agent_t *agent)
{
    return agent->stream->lpass->data;
}

const char *ice_get_ruser(ice_agent_t *agent)
{
    return agent->stream->ruser->data;
}

sbuf_t *ice_get_rpass(ice_agent_t *agent)
{
    return agent->stream->rpass;
}

uint32_t ice_get_ssrc(ice_agent_t *agent, int video)
{
    return video ? agent->stream->video_ssrc : agent->stream->audio_ssrc;
}


uint32_t get_priority(enum ice_candidate_type type, int local_preference, int component)
{
    int type_preference;
    if (type == ICE_CAND_TYPE_HOST)
        type_preference = 126;
    else if (type == ICE_CAND_TYPE_PRFLX)
        type_preference = 110;
    else if (type == ICE_CAND_TYPE_SRFLX)
        type_preference = 100;
    else /* relay */
        type_preference = 0;
    return (type_preference << 24) | (local_preference << 8) | component;
}

enum ice_payload_type ice_get_payload_type(const void *data, int size)
{
    if (size <= 2)
        return INVALID_ICE_PAYLOAD;
    const uint8_t *p = data;
    uint8_t rtp_payload = (p[1] & 0x7f);
    if (p[0] == 0 || p[0] == 1)
        return ICE_PAYLOAD_STUN;
    else if (p[0] >= 20 && p[0] <= 64)
        return ICE_PAYLOAD_DTLS;
    else if (rtp_payload < 64 || rtp_payload >= 96)
        return ICE_PAYLOAD_RTP;
    else if (rtp_payload >= 64 && rtp_payload < 96)
        return ICE_PAYLOAD_RTCP;
    else
        return ICE_PAYLOAD_DTLS; /* maybe SCTP */
}

void stun_handler(ice_server_t *srv, const void *data, int size,
                  const struct sockaddr *addr, socklen_t addrlen,
                  tcp_chan_t *tcp_chan)
{
    char host[NI_MAXHOST] = {};
    char serv[NI_MAXSERV] = {};
    int ret;

    getnameinfo(addr, addrlen, host, NI_MAXHOST,
                serv, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

    if (!stun_msg_verify(data, size)) {
        LLOG(LL_ERROR, "invalid stun msg from %s:%s", host, serv);
        return;
    }
    const stun_msg_hdr_t *msg_hdr = data;
    const stun_attr_hdr_t *attr_hdr = NULL;
    size_t attr_len;
    if (stun_msg_type(msg_hdr) == STUN_BINDING_REQUEST) {
        attr_hdr = stun_msg_find_attr(msg_hdr, STUN_ATTR_USERNAME);
        attr_len = stun_attr_len(attr_hdr);
        if (attr_len >= ICE_MAX_USERNAME_LENGTH) {
            LLOG(LL_ERROR, "stun:USERNAME len=%d too long", (int)attr_len);
            return;
        }
        char username[ICE_MAX_USERNAME_LENGTH], username_mirror[ICE_MAX_USERNAME_LENGTH];
        char ufrag1[ICE_MAX_USERNAME_LENGTH], ufrag2[ICE_MAX_USERNAME_LENGTH];
        if (attr_len < ICE_MAX_USERNAME_LENGTH) {
            memcpy(username, stun_attr_varsize_read((stun_attr_varsize_t*)attr_hdr), attr_len);
            username[attr_len] = 0;
        } else {
            memcpy(username, stun_attr_varsize_read((stun_attr_varsize_t*)attr_hdr), ICE_MAX_USERNAME_LENGTH - 1);
            username[ICE_MAX_USERNAME_LENGTH - 1] = 0;
        }
        int ret = sscanf(username, "%[^:]:%s", ufrag1, ufrag2);
        if (ret != 2) {
            LLOG(LL_ERROR, "stun:USERNAME split by ':' failed.");
            return;
        }

        ice_agent_t *agent = find_agent_by_username(srv, ufrag1);
        char reply_msg[256];
        stun_msg_hdr_t *reply_msg_hdr = (stun_msg_hdr_t*)reply_msg;
        if (!agent) {
            //LLOG(LL_ERROR, "stun binding request: ufrag=%s, from=%s:%s shard=%d, agent not found",
            //     ufrag1, host, serv, rtz_shard_get_index_ct());
            return;
        }

        // start DTLS handshake
        dtls_srtp_handshake(agent->stream->component->dtls);

        //LLOG(LL_TRACE, "stun binding request: ufrag=%s, from=%s:%s, agent founded",
        //     ufrag1, host, serv);
        sbuf_strcpy(agent->stream->ruser, ufrag2);
        memcpy(&agent->peer_addr, addr, addrlen);
        agent->peer_tcp = tcp_chan;
        struct ice_tcp_chan_udata *chan_udata = tcp_chan_get_userdata(tcp_chan);
        chan_udata->agent = agent;
        if (stun_msg_find_attr(msg_hdr, STUN_ATTR_USE_CANDIDATE))
            agent->cand_state = ICE_CAND_STATE_NOMINATED;
        else
            agent->cand_state = ICE_CAND_STATE_VALID;
        //LLOG(LL_TRACE, "update cand state to %s",
        //    (agent->cand_state == ICE_CAND_STATE_VALID) ? "VALID" : "NOMINATED");
        sprintf(username_mirror, "%s:%s", ufrag2, ufrag1);

        // STUN Response
        stun_msg_hdr_init(reply_msg_hdr, STUN_BINDING_RESPONSE, msg_hdr->tsx_id);
        stun_attr_xor_sockaddr_add(reply_msg_hdr, STUN_ATTR_XOR_MAPPED_ADDRESS, addr);
        stun_attr_varsize_add(reply_msg_hdr, STUN_ATTR_USERNAME,
                                username, strlen(username), ' ');
        stun_attr_empty_add(reply_msg_hdr, STUN_ATTR_USE_CANDIDATE);
        stun_attr_msgint_add(reply_msg_hdr, agent->stream->lpass->data, agent->stream->lpass->size);
        stun_attr_fingerprint_add(reply_msg_hdr);

        ice_send(agent, ICE_PACKET_STUN, reply_msg_hdr, stun_msg_len(reply_msg_hdr));
    #if 0
        // STUN Request
        if (!sbuf_empty(agent->stream->rpass)) {
            //LLOG(LL_TRACE, "send STUN request rpass=%s", agent->stream->rpass->data);
            reply_msg_hdr = (stun_msg_hdr_t*)reply_msg;
            stun_msg_hdr_init(reply_msg_hdr, STUN_BINDING_REQUEST, msg_hdr->tsx_id);
            stun_attr_uint64_add(reply_msg_hdr, STUN_ATTR_ICE_CONTROLLED, lrand48());
            stun_attr_varsize_add(reply_msg_hdr, STUN_ATTR_USERNAME,
                                  username_mirror, strlen(username_mirror), ' ');
            stun_attr_empty_add(reply_msg_hdr, STUN_ATTR_USE_CANDIDATE);
            stun_attr_msgint_add(reply_msg_hdr, agent->stream->rpass->data, agent->stream->rpass->size);
            stun_attr_fingerprint_add(reply_msg_hdr);
            ice_send(agent, ICE_PACKET_STUN, reply_msg_hdr, stun_msg_len(reply_msg_hdr));
        };
    #endif

    } else if (stun_msg_type(msg_hdr) == STUN_BINDING_RESPONSE) {
        //LLOG(LL_TRACE, "stun binding response from %s:%s", host, serv);
    } else if (stun_msg_type(msg_hdr) == STUN_BINDING_INDICATION) {
        //LLOG(LL_TRACE, "stun binding indication from %s:%s", host, serv);
    } else {
        LLOG(LL_WARN, "unhandled stun msg type %d", (int)stun_msg_type(msg_hdr));
    }
}

ice_agent_t *find_agent_by_username(ice_server_t *srv, const char *ufrag)
{
    ice_agent_t *agent;
    list_for_each_entry(agent, &srv->agent_list, link) {
        if (!strcmp(ufrag, agent->stream->luser->data))
            return agent;
    }
    return NULL;
}

ice_agent_t *find_agent_by_address(ice_server_t *srv, const struct sockaddr *addr, socklen_t addrlen, int tcp)
{
    ice_agent_t *agent;
    const struct sockaddr_in *addr_in = (const struct sockaddr_in*)addr;
    list_for_each_entry(agent, &srv->agent_list, link) {
        struct sockaddr_in *peer_addr = (struct sockaddr_in*)&agent->peer_addr;
        if (peer_addr->sin_port == addr_in->sin_port
            && peer_addr->sin_addr.s_addr == addr_in->sin_addr.s_addr)
            return agent;
    }
    return NULL;
}

void dtls_handler(ice_agent_t *agent, const void *data, int size,
                  const struct sockaddr *addr, socklen_t addrlen)
{
    if (!agent)
        return;
    ice_component_t *component = agent->stream->component;
    dtls_srtp_incoming_msg(component->dtls, (char*)data, (uint16_t)size);
}

void srtp_handler(ice_agent_t *agent, const void *data, int size)
{
    if (!agent)
        return;
    //LLOG(LL_TRACE, "srtp pkt len=%d", size);
    if (size < 12)
        return;
}

void srtcp_handler(ice_agent_t *agent, const void *data, int size)
{
    if (!agent)
        return;
    //LLOG(LL_TRACE, "srtcp pkt len=%d", size);
    if (size < 12)
        return;
    ice_stream_t *stream = agent->stream;
    ice_component_t *component = stream->component;
    if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_in) {
        LLOG(LL_WARN, "Missing valid SRTP session (packet arrived too early?), skipping...");
        return;
    }
    int buflen = size;
    char *buf = (void*)data;
    srtp_err_status_t res = srtp_unprotect_rtcp(component->dtls->srtp_in, buf, &buflen);
    if (res != srtp_err_status_ok) {
        LLOG(LL_ERROR, "SRTCP unprotect error: %s (len=%d-->%d)", rtz_srtp_error_str(res), size, buflen);
        return;
    }
    /* Check if there's an RTCP BYE: in case, let's log it */
    if (rtcp_has_bye(buf, buflen)) {
        LLOG(LL_ERROR, "Got RTCP BYE on stream %p (component %p)", component->stream, component);
    }
    /* Is this audio or video? */
    int video = 0, vindex = 0;
    /* Bundled streams, should we check the SSRCs? */
    if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_HAS_AUDIO)) {
        /* No audio has been negotiated, definitely video */
        //LLOG(LL_TRACE, "Incoming RTCP, bundling: this is video (no audio has been negotiated)");
        video = 1;
    } else if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_HAS_VIDEO)) {
        /* No video has been negotiated, definitely audio */
        //LLOG(LL_TRACE, "Incoming RTCP, bundling: this is audio (no video has been negotiated)");
        video = 0;
    } else {
        video = 1;
        /* We don't know the remote SSRC: this can happen for recvonly clients
         * (see https://groups.google.com/forum/#!topic/discuss-webrtc/5yuZjV7lkNc)
         * Check the local SSRC, compare it to what we have */
        uint32_t rtcp_ssrc = rtcp_get_receiver_ssrc(buf, buflen);
        if (rtcp_ssrc == 0) {
            /* No SSRC, maybe an empty RR? */
            return;
        }
        if (rtcp_ssrc == stream->audio_ssrc) {
            video = 0;
        } else if (rtcp_ssrc == stream->video_ssrc) {
            video = 1;
        } else if (rtcp_has_fir(buf, buflen) || rtcp_has_pli(buf, buflen) || rtcp_get_remb(buf, buflen)) {
            /* Mh, no SR or RR? Try checking if there's any FIR, PLI or REMB */
            video = 1;
        } else {
            LLOG(LL_WARN, "Dropping RTCP packet with unknown SSRC (%"SCNu32")", rtcp_ssrc);
            return;
        }
        //LLOG(LL_TRACE, "Incoming RTCP, bundling: this is %s (local SSRC: video=%"SCNu32", audio=%"SCNu32", got %"SCNu32")",
        //     video ? "video" : "audio", stream->video_ssrc, stream->audio_ssrc, rtcp_ssrc);
    }

    /* Let's process this RTCP (compound?) packet, and update the RTCP context for this stream in case */
    struct rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx : stream->audio_rtcp_ctx;
    rtcp_parse(rtcp_ctx, buf, buflen);
    //LLOG(LL_TRACE, "Got %s RTCP (%d bytes)", video ? "video" : "audio", buflen);
    rtcp_handler(agent, video, buf, buflen);
}

void ice_webrtc_hangup(ice_agent_t *handle, const char *reason)
{
    if (!handle)
        return;
    if (ice_flags_is_set(handle, ICE_HANDLE_WEBRTC_ALERT))
        return;
    ice_flags_set(handle, ICE_HANDLE_WEBRTC_ALERT);
    ice_flags_set(handle, ICE_HANDLE_WEBRTC_CLEANING);
    /* User will be notified only after the actual hangup */
    LLOG(LL_TRACE, "Hanging up PeerConnection because of a %s", reason);
    sbuf_strcpy(handle->hangup_reason, reason);
    if (handle->stream && handle->stream->component && ice_flags_is_set(handle, ICE_HANDLE_WEBRTC_READY)) {
        dtls_srtp_send_alert(handle->stream->component->dtls);
    }
    /* Stop RTCP timer */
    if (handle->rtcp_timer != -1) {
        //LLOG(LL_TRACE, "stop timer id=%d", handle->rtcp_timer);
        zl_timer_stop(handle->srv->loop, handle->rtcp_timer);
        handle->rtcp_timer = -1;
    }
    rtz_hangup(handle->rtz_handle);

#if 0
    /* Stop incoming traffic */
    if (handle->mainloop != NULL && handle->stream_id > 0) {
        nice_agent_attach_recv(handle->agent, handle->stream_id, 1, g_main_loop_get_context(handle->mainloop), NULL, NULL);
    }
    /* Let's message the loop, we'll notify the plugin from there */
    if (handle->queued_packets != NULL) {
    #if GLIB_CHECK_VERSION(2, 46, 0)
        g_async_queue_push_front(handle->queued_packets, &janus_ice_hangup_peerconnection);
    #else
        g_async_queue_push(handle->queued_packets, &janus_ice_hangup_peerconnection);
    #endif
        g_main_context_wakeup(handle->mainctx);
    }
#endif
}

void rtp_handler(ice_agent_t *agent, int video, const void *data, int size)
{
    //LLOG(LL_TRACE, "rtp pkt len=%d", size);
    if (size < 12)
        return;
}

void rtcp_handler(ice_agent_t *agent, int video, const void *data, int size)
{
    //LLOG(LL_TRACE, "agent %p handle %p rtcp pkt len=%d", agent, agent->rtz_handle, size);
    if (size < 12)
        return;
}

ice_stream_t * ice_get_stream(ice_agent_t *agent)
{
    return agent->stream;
}

ice_stream_t *ice_component_get_stream(ice_component_t *component)
{
    return component->stream;
}

int ice_component_send(ice_component_t *component, const void *data, int size)
{
    ice_agent_t *agent = component->stream->agent;
    if (!agent->cand_state) {
        if (!agent->no_errlog) {
            /* suppress error log */
            agent->no_errlog = 1;
            LLOG(LL_ERROR, "rtz_handle %p ice_agent %p component_send failed, no valid candidate pair.",
                 agent->rtz_handle, agent);
        }
        return -1;
    }
    struct sockaddr *addr = (struct sockaddr*)&agent->peer_addr;
    socklen_t slen = sizeof(struct sockaddr_in);
    if (agent->peer_tcp) {
        if (tcp_chan_get_write_buf_size(agent->peer_tcp) > ICE_MAX_TCP_WRITE_BUF_SIZE) {
            LLOG(LL_ERROR, "rtz_handle %p ice_agent %p slow connection, abort stun-tcp channel.",
                 agent->rtz_handle, agent);
            ice_tcp_error_cleanup(agent->peer_tcp, tcp_chan_get_userdata(agent->peer_tcp));
            return -1;
        }
        uint8_t frame_hdr[2];
        frame_hdr[0] = (size & 0xff00) >> 8;
        frame_hdr[1] = (size & 0xff);
        tcp_chan_write(agent->peer_tcp, frame_hdr, 2);
        tcp_chan_write(agent->peer_tcp, data, size);
        return size;
    }
    return -1;
}

ice_agent_t *ice_stream_get_agent(ice_stream_t *stream)
{
    return stream->agent;
}

sbuf_t *ice_stream_get_remote_hashing(ice_stream_t *stream)
{
    return stream->remote_hashing;
}

sbuf_t *ice_stream_get_remote_fingerprint(ice_stream_t *stream)
{
    return stream->remote_fingerprint;
}

void ice_dtls_handshake_done(ice_agent_t *agent, ice_component_t *component)
{
    LLOG(LL_TRACE, "handle %p ice_agent=%p dtls handshake done!", agent->rtz_handle, agent);
    if (ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_READY)) {
        /* Already notified */
        return;
    }
    ice_flags_set(agent, ICE_HANDLE_WEBRTC_READY);

    /* Create a source for RTCP and one for stats */
    agent->rtcp_timer = zl_timer_start(agent->srv->loop, 1000, 1000, rtcp_timeout_handler, agent);
    //LLOG(LL_TRACE, "start timer id=%d", agent->rtcp_timer);

    rtz_webrtcup(agent->rtz_handle);
}

void ice_flags_reset(ice_agent_t *agent)
{
    agent->flags = 0;
}

void ice_flags_set(ice_agent_t *agent, unsigned flag)
{
    agent->flags |= flag;
}

void ice_flags_clear(ice_agent_t *agent, unsigned flag)
{
    agent->flags &= ~flag;
}

int ice_flags_is_set(ice_agent_t *agent, unsigned flag)
{
    return (agent->flags & flag);
}

void ice_send_rtp(ice_agent_t *agent, int video, const void *data, int size)
{
    int type = video ? ICE_PACKET_VIDEO_RTP : ICE_PACKET_AUDIO_RTP;
    ice_send(agent, type, data, size);
}

void ice_send_rtcp(ice_agent_t *agent, int video, const void *data, int size)
{
    int type = video ? ICE_PACKET_VIDEO_RTCP : ICE_PACKET_AUDIO_RTCP;
    ice_send(agent, type, data, size);
}

void ice_send_dtls(ice_agent_t *agent, const void *data, int size)
{
    ice_send(agent, ICE_PACKET_DTLS, data, size);
}

void ice_prepare_video_keyframe(ice_agent_t *agent)
{
    if (!agent || ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_STOP)
        || ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_ALERT))
        return;
    int q = offsetof(ice_agent_t, pkt_list);
    ice_queued_packet_t *pkt, *tmp;
    int n, bytes = 0, need_drop = 0;
    list_for_each_entry(pkt, &agent->pkt_list, link) {
        bytes += pkt->length;
        if (bytes > DROP_THREHOLD) {
            need_drop = 1;
            break;
        }
    }
    if (need_drop) {
        n = 0;
        bytes = 0;
        list_for_each_entry_safe(pkt, tmp, &agent->pkt_list, link) {
            ++n;
            bytes += pkt->length;
            ice_free_queued_packet(pkt);
        }
        LLOG(LL_TRACE, "rtz_handle %p drop %d packets, bytes=%d",
             agent->rtz_handle, n, bytes);
    }
}

void ice_send(ice_agent_t *agent, int type, const void *data, int size)
{
    if (!data || size < 1)
        return;
    ice_queued_packet_t *pkt = malloc(sizeof(ice_queued_packet_t));
    pkt->data = malloc(size + SRTP_MAX_TAG_LEN + 4);
    memcpy(pkt->data, data, size);
    pkt->length = size;
    pkt->type = type;
    pkt->encrypted = 0;
    pkt->retransmission = 0;
    pkt->added = zl_hrtimestamp();
    INIT_LIST_HEAD(&pkt->link); /* Allow list_del() */
    ice_send_packet(agent, pkt);
}

void ice_send_packet(ice_agent_t *agent, ice_queued_packet_t *pkt)
{
    ice_stream_t *stream = agent->stream;
    ice_component_t *component = stream->component;
    if (pkt->type == ICE_PACKET_DTLS || pkt->type == ICE_PACKET_STUN) {
        /* Immediate send */
        ice_component_send(component, pkt->data, pkt->length);
        update_stats(component, pkt);
        ice_free_queued_packet(pkt);
    } else if (pkt->type == ICE_PACKET_AUDIO_RTCP || pkt->type == ICE_PACKET_VIDEO_RTCP) {
        /* RTCP */
        if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
            //if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_ALERT)/* && !component->noerrorlog*/) {
            //    LLOG(LL_WARN, "rtz_handle %p agent %p stream component has no valid SRTP session (yet?)",
            //         agent->rtz_handle, agent);
            //}
            ice_free_queued_packet(pkt);
            return;
        }

        if (pkt->encrypted) {
            /* Already SRTCP */
            ice_component_send(component, pkt->data, pkt->length);
            update_stats(component, pkt);
            ice_free_queued_packet(pkt);
        } else {
            int plen = pkt->length;
            int res = srtp_protect_rtcp(component->dtls->srtp_out, pkt->data, &plen);
            //LLOG(LL_TRACE, "encrypt %d -> %d", pkt->length, protected);
            if (res != srtp_err_status_ok) {
                /* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
                //handle->srtp_errors_count++;
                //handle->last_srtp_error = res;
                /* If we're debugging, though, print every occurrence */
                //LLOG(LL_DEBUG, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...", handle->handle_id, janus_srtp_error_str(res), pkt->length, plen);
                ice_free_queued_packet(pkt);
                return;
            }
            if (agent->peer_tcp && tcp_chan_get_write_buf_size(agent->peer_tcp)) {
                /* Queue to send later. */
                pkt->encrypted = 1;
                pkt->length = plen;
                list_add_tail(&pkt->link, &agent->pkt_list);
            } else {
                ice_component_send(component, pkt->data, plen);
                update_stats(component, pkt);
                ice_free_queued_packet(pkt);
            }
        }
    } else if (pkt->type == ICE_PACKET_AUDIO_RTP || pkt->type == ICE_PACKET_VIDEO_RTP) {
        /* RTP */
        //stream->noerrorlog = FALSE;
        if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
            //if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_ALERT)/* && !component->noerrorlog*/) {
            //    LLOG(LL_WARN, "rtz_handle %p agent %p has no valid SRTP session (yet?)",
            //         agent->rtz_handle, agent);
            //}
            ice_free_queued_packet(pkt);
            return;
        }

        if (pkt->encrypted) {
            /* Already SRTP */
            ice_component_send(component, pkt->data, pkt->length);
            update_stats(component, pkt);
            ice_free_queued_packet(pkt);
        } else {
            /* Overwrite SSRC */
            rtp_header *header = (rtp_header *)pkt->data;
            if (!pkt->retransmission) {
                /* ... but only if this isn't a retransmission (for those we already set it before) */
                header->ssrc = htonl((pkt->type == ICE_PACKET_VIDEO_RTP) ? stream->video_ssrc : stream->audio_ssrc);
            }

            if (agent->peer_tcp && tcp_chan_get_write_buf_size(agent->peer_tcp)) {
                /* Queue to send later. */
                list_add_tail(&pkt->link, &agent->pkt_list);
            } else {
                /* Overwrite seqno */
                if (!pkt->retransmission) {
                    if (pkt->type == ICE_PACKET_VIDEO_RTP) {
                        header->ssrc = htonl(stream->video_ssrc);
                        header->seq_number = htons(stream->video_seqno++);
                    } else {
                        header->ssrc = htonl(stream->audio_ssrc);
                        header->seq_number = htons(stream->audio_seqno++);
                    }
                }
                int plen = pkt->length;
                int res = srtp_protect(component->dtls->srtp_out, pkt->data, &plen);
                //LLOG(LL_TRACE, "encrypt %d -> %d", pkt->length, plen);
                if (res == srtp_err_status_ok) {
                    ice_component_send(component, pkt->data, plen);
                    update_stats(component, pkt);
                }
                ice_free_queued_packet(pkt);
            }
        }

    } else {
        ice_free_queued_packet(pkt);
    }
}

void ice_free_queued_packet(ice_queued_packet_t *pkt)
{
    if (!pkt)
        return;
    list_del(&pkt->link);
    free(pkt->data);
    free(pkt);
}

void rtcp_timeout_handler(zl_loop_t *loop, int id, void *udata)
{
    //LLOG(LL_TRACE, "rtcp timeout...");
    ice_agent_t *handle = (ice_agent_t*)udata;
    ice_stream_t *stream = handle->stream;
    /* Video */
    if (stream && stream->component && stream->component->out_stats.video.packets > 0) {
        //LLOG(LL_TRACE, "    send video SR/SDES");
        /* Create a SR/SDES compound */
        int srlen = 28;
        int sdeslen = 20;
        char rtcpbuf[srlen + sdeslen];
        memset(rtcpbuf, 0, sizeof(rtcpbuf));
        rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
        sr->header.version = 2;
        sr->header.type = RTCP_SR;
        sr->header.rc = 0;
        sr->header.length = htons((srlen / 4) - 1);
        sr->ssrc = htonl(stream->video_ssrc);
        struct timeval tv;
        gettimeofday(&tv, NULL);
        /* There is 70 years (incl. 17 leap ones) offset to the Unix Epoch.
         * No leap seconds during that period since they were not invented yet.
         * (70 * 365 + 17) * 24 * 60 * 60 = 2208988800
         */
        uint32_t s = tv.tv_sec + 2208988800u;
        uint32_t u = tv.tv_usec;
        /* convert from micro-sec to 32 bit fraction  */
        uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
        sr->si.ntp_ts_msw = htonl(s);
        sr->si.ntp_ts_lsw = htonl(f);
        /* Compute an RTP timestamp coherent with the NTP one */
        rtcp_context *rtcp_ctx = stream->video_rtcp_ctx;
        if (rtcp_ctx == NULL) {
            //LLOG(LL_TRACE, "video: NULL rtcp_ctx, rtp_ts=%u", stream->video_last_ts);
            sr->si.rtp_ts = htonl(stream->video_last_ts);	/* FIXME */
        } else {
            int64_t ntp = tv.tv_sec * ZL_USEC_PER_SEC + tv.tv_usec;
            uint32_t rtp_ts = ((ntp - stream->video_first_ntp_ts)*(rtcp_ctx->tb)) / 1000000 + stream->video_first_rtp_ts;
            //LLOG(LL_TRACE, "video: tb=%u rtp_ts=%u", rtcp_ctx->tb, rtp_ts);
            sr->si.rtp_ts = htonl(rtp_ts);
        }
        sr->si.s_packets = htonl(stream->component->out_stats.video.packets);
        sr->si.s_octets = htonl(stream->component->out_stats.video.bytes);
        rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
        rtcp_sdes_cname((char *)sdes, sdeslen, "rtz", 3);
        sdes->chunk.ssrc = htonl(stream->video_ssrc);
        ice_send_rtcp(handle, 1, rtcpbuf, srlen + sdeslen);
    }
    /* DO NOT send Audio SR, inaccurate timestamp will cause A/V sync issue in chrome */
#if 0
    if (stream && stream->component && stream->component->out_stats.audio.packets > 0) {
        //LLOG(LL_TRACE, "    send audio SR/SDES");
        /* Create a SR/SDES compound */
        int srlen = 28;
        int sdeslen = 20;
        char rtcpbuf[srlen + sdeslen];
        memset(rtcpbuf, 0, sizeof(rtcpbuf));
        rtcp_sr *sr = (rtcp_sr *)&rtcpbuf;
        sr->header.version = 2;
        sr->header.type = RTCP_SR;
        sr->header.rc = 0;
        sr->header.length = htons((srlen / 4) - 1);
        sr->ssrc = htonl(stream->audio_ssrc);
        struct timeval tv;
        gettimeofday(&tv, NULL);
        uint32_t s = tv.tv_sec + 2208988800u;
        uint32_t u = tv.tv_usec;
        uint32_t f = (u << 12) + (u << 8) - ((u * 3650) >> 6);
        sr->si.ntp_ts_msw = htonl(s);
        sr->si.ntp_ts_lsw = htonl(f);
        /* Compute an RTP timestamp coherent with the NTP one */
        rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
        if (rtcp_ctx == NULL) {
            LLOG(LL_TRACE, "audio: NULL rtcp_ctx, rtp_ts=%u", stream->audio_last_ts);
            sr->si.rtp_ts = htonl(stream->audio_last_ts);	/* FIXME */
        } else {
            int64_t ntp = tv.tv_sec * ZL_USEC_PER_SEC + tv.tv_usec;
            uint32_t rtp_ts = ((ntp - stream->audio_first_ntp_ts)*(rtcp_ctx->tb)) / 1000000 + stream->audio_first_rtp_ts;
            LLOG(LL_TRACE, "audio: tb=%u rtp_ts=%u", rtcp_ctx->tb, rtp_ts);
            sr->si.rtp_ts = htonl(rtp_ts);
        }
        sr->si.s_packets = htonl(stream->component->out_stats.audio.packets);
        sr->si.s_octets = htonl(stream->component->out_stats.audio.bytes);
        rtcp_sdes *sdes = (rtcp_sdes *)&rtcpbuf[28];
        rtcp_sdes_cname((char *)sdes, sdeslen, "rtz", 3);
        sdes->chunk.ssrc = htonl(stream->audio_ssrc);
        ice_send_rtcp(handle, 0, rtcpbuf, srlen + sdeslen);
    }
#endif
}

void ice_tcp_error_cleanup(tcp_chan_t *chan, struct ice_tcp_chan_udata *chan_udata)
{
    ice_agent_t *agent;
    list_for_each_entry(agent, &chan_udata->srv->agent_list, link) {
        if (agent->peer_tcp == chan) {
            agent->peer_tcp = NULL;
            agent->cand_state = ICE_CAND_STATE_EMPTY;
            agent->no_errlog = 0;
            //ice_webrtc_hangup(agent, "TcpSocket Error");
        }
    }
    free(chan_udata);
    tcp_chan_close(chan, 0);
}

static int peek_stun_binding_request(const void *data, int size, char *username)
{
    enum ice_payload_type type = ice_get_payload_type(data, size);
    if (type == ICE_PAYLOAD_STUN) {
        if (!stun_msg_verify(data, size))
            return 0;
        const stun_msg_hdr_t *msg_hdr = data;
        const stun_attr_hdr_t *attr_hdr = NULL;
        size_t attr_len;
        if (stun_msg_type(msg_hdr) == STUN_BINDING_REQUEST) {
            attr_hdr = stun_msg_find_attr(msg_hdr, STUN_ATTR_USERNAME);
            attr_len = stun_attr_len(attr_hdr);
            if (attr_len >= ICE_MAX_USERNAME_LENGTH) {
                LLOG(LL_ERROR, "stun:USERNAME len=%d too long", (int)attr_len);
                return 0;
            }
            if (attr_len < ICE_MAX_USERNAME_LENGTH) {
                memcpy(username, stun_attr_varsize_read((stun_attr_varsize_t*)attr_hdr), attr_len);
                username[attr_len] = 0;
            } else {
                memcpy(username, stun_attr_varsize_read((stun_attr_varsize_t*)attr_hdr), ICE_MAX_USERNAME_LENGTH - 1);
                username[ICE_MAX_USERNAME_LENGTH - 1] = 0;
            }
            return 1;
        }
    }
    return 0;
}

static int ice_get_username_shard_index(const char *username)
{
    int p0 = username[0] - 'A';
    if (p0 >= 0 && p0 < MAX_RTZ_SHARDS)
        return p0;
    return -1;
}

/** Call on target thread loop */
static void move_tcp_chan(zl_loop_t *loop, void *udata)
{
    tcp_chan_t *chan = udata;
    rtz_server_t *srv = rtz_shard_get_server_ct();
    //LLOG(LL_TRACE, "tcp_chan %p moved", chan);
    tcp_chan_set_usertag(chan, 1);
    struct ice_tcp_chan_udata *chan_udata = tcp_chan_get_userdata(chan);
    chan_udata->srv = rtz_get_ice_server(srv);
    tcp_chan_attach(chan, loop);
}

void ice_tcp_data_handler(tcp_chan_t *chan, void *udata)
{
    struct ice_tcp_chan_udata *chan_udata = udata;
    uint8_t data[2 + ICE_MAX_TCP_FRAME_SIZE];
    int qlen = tcp_chan_get_read_buf_size(chan);
    int size;

    if (!tcp_chan_get_usertag(chan)) {
        if (qlen >= 2) {
            tcp_chan_peek(chan, data, 2);
            size = (data[0] << 8) | data[1];
            if (qlen >= 2 + size) {
                tcp_chan_peek(chan, data, 2 + size);
                char username[ICE_MAX_USERNAME_LENGTH];
                if (peek_stun_binding_request(data + 2, size, username)) {
                    char *p = strchr(username, ':');
                    if (p)
                        *p = 0;
                    int cur_shard = rtz_shard_get_index_ct();
                    int expect_shard = ice_get_username_shard_index(username);
                    assert(cur_shard != -1);
                    assert(expect_shard != -1);
                    if (cur_shard != expect_shard) {
                        tcp_chan_detach(chan);
                        chan_udata->srv = NULL;
                        zl_loop_t *expect_loop = rtz_shard_get_loop(expect_shard);
                        if (expect_loop)
                            zl_invoke(expect_loop, move_tcp_chan, chan);
                        return;
                    } else {
                        tcp_chan_set_usertag(chan, 1);
                    }
                }
            }
        }
    }

    struct sockaddr_in addr_in;
    struct sockaddr *addr = (struct sockaddr*)&addr_in;
    int addrlen = sizeof(struct sockaddr_in);
    tcp_chan_get_peername(chan, addr, addrlen);

    while (qlen >= 2) {
        tcp_chan_peek(chan, data, 2);
        size = (data[0] << 8) | data[1];
        if (size > ICE_MAX_TCP_FRAME_SIZE) {
            ice_tcp_error_cleanup(chan, chan_udata);
            break;
        }
        if (qlen >= 2 + size) {
            tcp_chan_read(chan, data, 2 + size);
            enum ice_payload_type type = ice_get_payload_type(data + 2, size);
            //LLOG(LL_DEBUG, "pkt type %d size %d data=%02hhx%02hhx", type, size, ((uint8_t*)data)[2], ((uint8_t*)data)[3]);
            if (type == ICE_PAYLOAD_STUN) {
                stun_handler(chan_udata->srv, data + 2, size, addr, addrlen, chan);
            } else if (type == ICE_PAYLOAD_DTLS) {
                dtls_handler(chan_udata->agent, data + 2, size, addr, addrlen);
            } else if (type == ICE_PAYLOAD_RTP) {
                srtp_handler(chan_udata->agent, data + 2, size);
            } else if (type == ICE_PAYLOAD_RTCP) {
                srtcp_handler(chan_udata->agent, data + 2, size);
            } else {
                LLOG(LL_WARN, "unhandled muxed payload type=%d", type);
            }
            if (chan_udata->agent)
                rtz_update_stats(chan_udata->agent->rtz_handle, 2 + size, 0);
        } else {
            break;
        }
        qlen = tcp_chan_get_read_buf_size(chan);
    }
}

void ice_tcp_sent_handler(tcp_chan_t *chan, void *udata)
{
    int qlen = tcp_chan_get_write_buf_size(chan);
    if (qlen > 0)
        return;

    struct ice_tcp_chan_udata *chan_udata = udata;
    ice_agent_t *agent = chan_udata->agent;
    //struct sockaddr_in addr_in;
    //struct sockaddr *addr = (struct sockaddr*)&addr_in;
    //int addrlen = sizeof(struct sockaddr_in);
    //tcp_chan_get_peername(chan, addr, addrlen);
    //ice_agent_t *agent = find_agent_by_address(chan_udata->srv, addr, addrlen, 1);
    if (!agent)
        return;

    ice_stream_t *stream = agent->stream;
    ice_component_t *component = stream->component;
    ice_queued_packet_t *pkt, *tmp;
    int n = 0, bytes = 0;
    list_for_each_entry_safe(pkt, tmp, &agent->pkt_list, link) {
        /* Overwrite seqno */
        if (!pkt->retransmission) {
            rtp_header *header = (rtp_header*)pkt->data;
            if (pkt->type == ICE_PACKET_VIDEO_RTP)
                header->seq_number = htons(stream->video_seqno++);
            else
                header->seq_number = htons(stream->audio_seqno++);
            if (!pkt->encrypted) {
                int plen = pkt->length;
                int res;
                if (pkt->type == ICE_PACKET_AUDIO_RTP || pkt->type == ICE_PACKET_VIDEO_RTP)
                    res = srtp_protect(component->dtls->srtp_out, pkt->data, &plen);
                else if (pkt->type == ICE_PACKET_AUDIO_RTCP || pkt->type == ICE_PACKET_VIDEO_RTCP)
                    res = srtp_protect_rtcp(component->dtls->srtp_out, pkt->data, &plen);
                //LLOG(LL_TRACE, "encrypt %d -> %d", pkt->length, plen);
                if (res == srtp_err_status_ok) {
                    pkt->encrypted = 1;
                    pkt->length = plen;
                } else {
                    ice_free_queued_packet(pkt);
                    continue;
                }
            }
        }

        ++n;
        bytes += pkt->length;
        ice_component_send(component, pkt->data, pkt->length);
        update_stats(component, pkt);
        ice_free_queued_packet(pkt);
        if (bytes > MAX_PER_SEND_SIZE)
            break;
    }
    //if (n > 0)
    //    LLOG(LL_TRACE, "sent %d pkts, bytes=%d", n, bytes);
}

void ice_tcp_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    ice_tcp_error_cleanup(chan, udata);
}

/** Update stats */
void update_stats(ice_component_t *component, ice_queued_packet_t *pkt)
{
    /* Update the RTCP context as well */
    ice_stream_t *stream = component->stream;
    rtp_header *header = (rtp_header*)pkt->data;
    uint32_t timestamp = ntohl(header->timestamp);
    if (pkt->type == ICE_PACKET_AUDIO_RTP) {
        component->out_stats.audio.packets++;
        component->out_stats.audio.bytes += pkt->length;
        /* Last second outgoing audio */
        long long now = zl_hrtimestamp();
        if (component->out_stats.audio.updated == 0)
            component->out_stats.audio.updated = now;
        if (now > component->out_stats.audio.updated &&
            now - component->out_stats.audio.updated >= ZL_USEC_PER_SEC) {
            component->out_stats.audio.bytes_lastsec = component->out_stats.audio.bytes_lastsec_temp;
            component->out_stats.audio.bytes_lastsec_temp = 0;
            component->out_stats.audio.updated = now;
        }
        component->out_stats.audio.bytes_lastsec_temp += pkt->length;
        stream->audio_last_ts = timestamp;
        if (stream->audio_first_ntp_ts == 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            stream->audio_first_ntp_ts = (int64_t)tv.tv_sec * ZL_USEC_PER_SEC + tv.tv_usec;
            stream->audio_first_rtp_ts = timestamp;
        }
        /* Let's check if this was G.711: in case we may need to change the timestamp base */
        rtcp_context *rtcp_ctx = stream->audio_rtcp_ctx;
        int pt = header->type;
        if ((pt == 0 || pt == 8) && (rtcp_ctx->tb == 48000))
            rtcp_ctx->tb = 8000;
        /* Update sent packets counter */
        ++rtcp_ctx->sent_packets_since_last_rr;
    } else if (pkt->type == ICE_PACKET_VIDEO_RTP) {
        component->out_stats.video.packets++;
        component->out_stats.video.bytes += pkt->length;
        /* Last second outgoing video */
        long long now = zl_hrtimestamp();
        if (component->out_stats.video.updated == 0)
            component->out_stats.video.updated = now;
        if (now > component->out_stats.video.updated &&
            now - component->out_stats.video.updated >= ZL_USEC_PER_SEC) {
            component->out_stats.video.bytes_lastsec = component->out_stats.video.bytes_lastsec_temp;
            component->out_stats.video.bytes_lastsec_temp = 0;
            component->out_stats.video.updated = now;
        }
        component->out_stats.video.bytes_lastsec_temp += pkt->length;
        stream->video_last_ts = timestamp;
        if (stream->video_first_ntp_ts == 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            stream->video_first_ntp_ts = (int64_t)tv.tv_sec * ZL_USEC_PER_SEC + tv.tv_usec;
            stream->video_first_rtp_ts = timestamp;
        }
        /* Update sent packets counter */
        ++stream->video_rtcp_ctx->sent_packets_since_last_rr;
    }

    int len = pkt->length;
    if (stream->agent->peer_tcp)
        len += 2; /* 2 bytes frame header */
    rtz_update_stats(stream->agent->rtz_handle, 0, len);
}
