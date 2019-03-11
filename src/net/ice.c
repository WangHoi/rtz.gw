#include "ice.h"
#include "sbuf.h"
#include "event_loop.h"
#include "udp_chan.h"
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
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cJSON.h>

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

enum ice_payload_type {
    INVALID_ICE_PAYLOAD = -1,
    ICE_PAYLOAD_STUN,
    ICE_PAYLOAD_DTLS,
    ICE_PAYLOAD_RTP,
    ICE_PAYLOAD_RTCP,
};

enum {
    ICE_UFRAG_LENGTH = 4,
    ICE_PWD_LENGTH = 22,
    ICE_MAX_LOCAL_PREFERENCE = 65535,
    ICE_MAX_USERNAME_LENGTH = 32,
    ICE_MAX_TCP_FRAME_SIZE = 1500,
    ICE_MAX_TCP_WRITE_BUF_SIZE = 2 << 20,
};

#define JANUS_ICE_PACKET_AUDIO	0
#define JANUS_ICE_PACKET_VIDEO	1
#define JANUS_ICE_PACKET_DATA	2
#define JANUS_ICE_PACKET_SCTP	3
/* Enqueued (S)RTP/(S)RTCP packet to send */
typedef struct ice_queued_packet {
    char *data;
    int length;
    int type;
    int control;
    int retransmission;
    int encrypted;
    int64_t added;
} ice_queued_packet;

/** Janus media statistics
 * @note To improve with more stuff */
typedef struct ice_stats_info {
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
} ice_stats_info;

/** Janus media statistics container
 * @note To improve with more stuff */
typedef struct ice_stats {
    /** Audio info */
    ice_stats_info audio;
    /** Video info (considering we may be simulcasting) */
    ice_stats_info video;
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
    udp_chan_t *udp_chan;
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
    /** Video SSRC of the server for this stream */
    uint32_t video_ssrc;
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
    /* TODO: refactor to ice_component_t */
    tcp_chan_t *peer_tcp;
    int cand_state;
    struct list_head link;
};

static ice_stream_t *ice_stream_new(ice_agent_t *handle);
static void ice_stream_del(ice_stream_t *stream);
static ice_component_t *ice_component_new(ice_stream_t *stream);
static void ice_component_del(ice_component_t *component);
static void ice_udp_data_handler(udp_chan_t *chan, const void *data, int size,
                              const struct sockaddr *dest_addr, socklen_t addrlen,
                              void *udata);
static void ice_udp_error_handler(udp_chan_t *chan, int status, void *udata);
static uint32_t get_priority(enum ice_candidate_type type, int local_preference, int component);
static enum ice_payload_type get_payload_type(const void *data, int size);
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
static void ice_free_queued_packet(ice_queued_packet *pkt);
static void ice_send_packet(ice_agent_t *agent, ice_queued_packet *pkt);
static void rtcp_timeout_handler(zl_loop_t *loop, int id, void *udata);
static void ice_tcp_accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata);
static void ice_tcp_data_handler(tcp_chan_t *chan, void *udata);
static void ice_tcp_error_handler(tcp_chan_t *chan, int status, void *udata);
static void ice_tcp_error_cleanup(tcp_chan_t *chan, ice_server_t *srv);

ice_server_t *ice_server_new(zl_loop_t *loop)
{
    ice_server_t *srv = malloc(sizeof(ice_server_t));
    memset(srv, 0, sizeof(ice_server_t));
    srv->loop = loop;
    srv->ip = sbuf_new1(16);
    sbuf_strcpy(srv->ip, "0.0.0.0");
    srv->udp_chan = udp_chan_new(loop);
    set_socket_send_buf_size(udp_chan_fd(srv->udp_chan), 1 << 16);
    srv->tcp_srv = tcp_srv_new(loop);
    INIT_LIST_HEAD(&srv->agent_list);
    return srv;
}

void ice_server_del(ice_server_t *srv)
{
    tcp_srv_del(srv->tcp_srv);
    udp_chan_close(srv->udp_chan);
    sbuf_del(srv->ip);
    free(srv);
}

void ice_server_bind(ice_server_t *srv, const char *ip, unsigned short port)
{
    sbuf_strcpy(srv->ip, ip);
    srv->port = port;
    udp_chan_bind(srv->udp_chan, ip, port);
    tcp_srv_bind(srv->tcp_srv, ip, port);
}

void ice_tcp_accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    ice_server_t *srv = udata;
    tcp_chan_set_cb(chan, ice_tcp_data_handler, NULL, ice_tcp_error_handler, srv);
    //tcp_chan_set_sndbuf(chan, 1 << 20);
}

void ice_server_start(ice_server_t *srv)
{
    udp_chan_set_cb(srv->udp_chan, ice_udp_data_handler, ice_udp_error_handler, srv);
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
    LLOG(LL_TRACE, "create agent luser=%s", agent->stream->luser->data);
    return agent;
}

void ice_agent_del(ice_agent_t *handle)
{
    if (!handle)
        return;
    LLOG(LL_TRACE, "release agent %p luser='%s'", handle, handle->stream->luser->data);
    if (handle->peer_tcp)
        tcp_chan_close(handle->peer_tcp, 0);
    ice_webrtc_hangup(handle, "Delete ICE Agent");
    ice_flags_set(handle, ICE_HANDLE_WEBRTC_STOP);
    ice_stream_del(handle->stream);
    sbuf_del(handle->hangup_reason);
    list_del(&handle->link);
    free(handle);
}

ice_stream_t *ice_stream_new(ice_agent_t *handle)
{
    ice_stream_t *stream = malloc(sizeof(ice_stream_t));
    memset(stream, 0, sizeof(ice_stream_t));
    stream->agent = handle;
    stream->audio_codec = sbuf_new();
    stream->video_codec = sbuf_new();
    stream->luser = sbuf_random_string(ICE_UFRAG_LENGTH);
    stream->lpass = sbuf_random_string(ICE_PWD_LENGTH);
    stream->remote_hashing = sbuf_new();
    stream->remote_fingerprint = sbuf_new();
    stream->ruser = sbuf_new1(ICE_UFRAG_LENGTH + 1);
    stream->rpass = sbuf_new1(ICE_PWD_LENGTH + 1);
    stream->audio_ssrc = (uint32_t)lrand48();
    stream->video_ssrc = (uint32_t)lrand48();
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

//void ice_get_local_candiate(ice_agent_t *agent, sbuf_t *b)
//{
//    uint32_t priority = get_priority(ICE_CAND_TYPE_HOST, ICE_MAX_LOCAL_PREFERENCE, 1);
//    sbuf_printf(b, "candidate %d %d %s %u %s %hu typ host",
//                1, 1, "udp", priority, agent->srv->ip->data, agent->srv->udp_port);
//}

void ice_udp_data_handler(udp_chan_t *chan, const void *data, int size,
                          const struct sockaddr *dest_addr, socklen_t addrlen,
                          void *udata)
{
    if (dest_addr->sa_family != AF_INET)
        return;

    ice_server_t *srv = udata;
    ice_agent_t *agent = find_agent_by_address(srv, dest_addr, addrlen, 0);
    enum ice_payload_type type = get_payload_type(data, size);
    if (type == ICE_PAYLOAD_STUN) {
        stun_handler(srv, data, size, dest_addr, addrlen, NULL);
    } else if (type == ICE_PAYLOAD_DTLS) {
        dtls_handler(agent, data, size, dest_addr, addrlen);
    } else if (type == ICE_PAYLOAD_RTP) {
        srtp_handler(agent, data, size);
    } else if (type == ICE_PAYLOAD_RTCP) {
        srtcp_handler(agent, data, size);
    } else {
        LLOG(LL_WARN, "unhandled muxed payload type=%d", type);
    }
}

void ice_udp_error_handler(udp_chan_t *chan, int status, void *udata)
{
    LLOG(LL_ERROR, "udp_chan event %d", status);
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

enum ice_payload_type get_payload_type(const void *data, int size)
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
            LLOG(LL_ERROR, "stun binding request: ufrag=%s, from=%s:%s, agent not found",
                 ufrag1, host, serv);
            return;
        }
        // start DTLS handshake
        dtls_srtp_handshake(agent->stream->component->dtls);

        //LLOG(LL_TRACE, "stun binding request: ufrag=%s, from=%s:%s, agent founded",
        //     ufrag1, host, serv);
        sbuf_strcpy(agent->stream->ruser, ufrag2);
        memcpy(&agent->peer_addr, addr, addrlen);
        agent->peer_tcp = tcp_chan;
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
        stun_attr_msgint_add(reply_msg_hdr, agent->stream->lpass->data, agent->stream->lpass->size);
        stun_attr_fingerprint_add(reply_msg_hdr);

        if (tcp_chan) {
            size_t reply_msg_len = stun_msg_len(reply_msg_hdr);
            uint8_t frame_hdr[2];
            frame_hdr[0] = (reply_msg_len & 0xff00) >> 8;
            frame_hdr[1] = (reply_msg_len & 0xff);
            tcp_chan_write(tcp_chan, frame_hdr, 2);
            tcp_chan_write(tcp_chan, reply_msg_hdr, reply_msg_len);
        } else {
            udp_chan_write(srv->udp_chan, reply_msg_hdr, stun_msg_len(reply_msg_hdr),
                           addr, addrlen);
        }
    #if 0
        // STUN Request
        if (!sbuf_empty(agent->stream->rpass)) {
            //LLOG(LL_TRACE, "send STUN request rpass=%s", agent->stream->rpass->data);
            reply_msg_hdr = (stun_msg_hdr_t*)reply_msg;
            stun_msg_hdr_init(reply_msg_hdr, STUN_BINDING_REQUEST, msg_hdr->tsx_id);
            stun_attr_uint64_add(reply_msg_hdr, STUN_ATTR_ICE_CONTROLLED, lrand48());
            stun_attr_varsize_add(reply_msg_hdr, STUN_ATTR_USERNAME,
                                  username_mirror, strlen(username_mirror), ' ');
            stun_attr_msgint_add(reply_msg_hdr, agent->stream->rpass->data, agent->stream->rpass->size);
            stun_attr_fingerprint_add(reply_msg_hdr);
            if (tcp_chan) {
                size_t reply_msg_len = stun_msg_len(reply_msg_hdr);
                uint8_t frame_hdr[2];
                frame_hdr[0] = (reply_msg_len & 0xff00) >> 8;
                frame_hdr[1] = (reply_msg_len & 0xff);
                tcp_chan_write(tcp_chan, frame_hdr, 2);
                tcp_chan_write(tcp_chan, reply_msg_hdr, reply_msg_len);
            } else {
                udp_chan_write(srv->udp_chan, reply_msg_hdr, stun_msg_len(reply_msg_hdr),
                               addr, addrlen);
            }
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
        if (peer_addr->sin_addr.s_addr == addr_in->sin_addr.s_addr
                && peer_addr->sin_port == addr_in->sin_port)
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
        LLOG(LL_ERROR, "SRTCP unprotect error: %s (len=%d-->%d)\n", rtz_srtp_error_str(res), size, buflen);
        return;
    }
    /* Check if there's an RTCP BYE: in case, let's log it */
    if (rtcp_has_bye(buf, buflen)) {
        /* Note: we used to use this as a trigger to close the PeerConnection, but not anymore
         * Discussion here, https://groups.google.com/forum/#!topic/meetecho-janus/4XtfbYB7Jvc */
        LLOG(LL_ERROR, "Got RTCP BYE on stream %p (component %p)\n", component->stream, component);
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

#if 0
    /* Now let's see if there are any NACKs to handle */
    long long now = zl_hrtime();
    GSList *nacks = janus_rtcp_get_nacks(buf, buflen);
    guint nacks_count = g_slist_length(nacks);
    if (nacks_count && ((!video && component->do_audio_nacks) || (video && component->do_video_nacks))) {
        /* Handle NACK */
        JANUS_LOG(LL_TRACE, "[%"SCNu64"]     Just got some NACKS (%d) we should handle...\n", handle->handle_id, nacks_count);
        GHashTable *retransmit_seqs = (video ? component->video_retransmit_seqs : component->audio_retransmit_seqs);
        GSList *list = (retransmit_seqs != NULL ? nacks : NULL);
        int retransmits_cnt = 0;
        janus_mutex_lock(&component->mutex);
        while (list) {
            unsigned int seqnr = GPOINTER_TO_UINT(list->data);
            JANUS_LOG(LL_DEBUG, "[%"SCNu64"]   >> %u\n", handle->handle_id, seqnr);
            int in_rb = 0;
            /* Check if we have the packet */
            janus_rtp_packet *p = g_hash_table_lookup(retransmit_seqs, GUINT_TO_POINTER(seqnr));
            if (p == NULL) {
                JANUS_LOG(LL_TRACE, "[%"SCNu64"]   >> >> Can't retransmit packet %u, we don't have it...\n", handle->handle_id, seqnr);
            } else {
                /* Should we retransmit this packet? */
                if ((p->last_retransmit > 0) && (now - p->last_retransmit < MAX_NACK_IGNORE)) {
                    JANUS_LOG(LL_TRACE, "[%"SCNu64"]   >> >> Packet %u was retransmitted just %"SCNi64"ms ago, skipping\n", handle->handle_id, seqnr, now - p->last_retransmit);
                    list = list->next;
                    continue;
                }
                in_rb = 1;
                JANUS_LOG(LL_TRACE, "[%"SCNu64"]   >> >> Scheduling %u for retransmission due to NACK\n", handle->handle_id, seqnr);
                p->last_retransmit = now;
                retransmits_cnt++;
                /* Enqueue it */
                janus_ice_queued_packet *pkt = g_malloc(sizeof(janus_ice_queued_packet));
                pkt->data = g_malloc(p->length + SRTP_MAX_TAG_LEN);
                memcpy(pkt->data, p->data, p->length);
                pkt->length = p->length;
                pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
                pkt->control = FALSE;
                pkt->retransmission = TRUE;
                pkt->added = janus_get_monotonic_time();
                /* What to send and how depends on whether we're doing RFC4588 or not */
                if (!video || !ice_flags_is_set(agent, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
                    /* We're not: just clarify the packet was already encrypted before */
                    pkt->encrypted = TRUE;
                } else {
                    /* We are: overwrite the RTP header (which means we'll need a new SRTP encrypt) */
                    janus_rtp_header *header = (janus_rtp_header *)pkt->data;
                    header->type = stream->video_rtx_payload_type;
                    header->ssrc = htonl(stream->video_ssrc_rtx);
                    component->rtx_seq_number++;
                    header->seq_number = htons(component->rtx_seq_number);
                }
                if (handle->queued_packets != NULL)
                #if GLIB_CHECK_VERSION(2, 46, 0)
                    g_async_queue_push_front(handle->queued_packets, pkt);
            #else
                    g_async_queue_push(handle->queued_packets, pkt);
            #endif
            }
            if (rtcp_ctx != NULL && in_rb) {
                g_atomic_int_inc(&rtcp_ctx->nack_count);
            }
            list = list->next;
        }
        component->retransmit_recent_cnt += retransmits_cnt;
        /* FIXME Remove the NACK compound packet, we've handled it */
        buflen = janus_rtcp_remove_nacks(buf, buflen);
        /* Update stats */
        if (video) {
            component->in_stats.video[vindex].nacks += nacks_count;
        } else {
            component->in_stats.audio.nacks += nacks_count;
        }
        /* Inform the plugin about the slow uplink in case it's needed */
        //janus_slow_link_update(component, handle, retransmits_cnt, video, 1, now);
        //janus_mutex_unlock(&component->mutex);
        g_slist_free(nacks);
        nacks = NULL;
    }
#endif
#if 0
    if (component->retransmit_recent_cnt &&
        now - component->retransmit_log_ts > 5 * ZL_USEC_PER_SEC) {
        JANUS_LOG(LOG_VERB, "[%"SCNu64"] Retransmitted %u packets due to NACK (%s stream #%d)\n",
                  handle->handle_id, component->retransmit_recent_cnt, video ? "video" : "audio", vindex);
        component->retransmit_recent_cnt = 0;
        component->retransmit_log_ts = now;
    }
#endif // skip NACK processing

#if 0
    /* Fix packet data for RTCP SR and RTCP RR */
    janus_rtp_switching_context *rtp_ctx = video ? &stream->rtp_ctx[vindex] : &stream->rtp_ctx[0];
    uint32_t base_ts = video ? rtp_ctx->v_base_ts : rtp_ctx->a_base_ts;
    uint32_t base_ts_prev = video ? rtp_ctx->v_base_ts_prev : rtp_ctx->a_base_ts_prev;
    uint32_t ssrc_peer = video ? stream->video_ssrc_peer_orig[vindex] : stream->audio_ssrc_peer_orig;
    uint32_t ssrc_local = video ? stream->video_ssrc : stream->audio_ssrc;
    uint32_t ssrc_expected = video ? rtp_ctx->v_last_ssrc : rtp_ctx->a_last_ssrc;
    if (janus_rtcp_fix_report_data(buf, buflen, base_ts, base_ts_prev, ssrc_peer, ssrc_local, ssrc_expected, video) < 0) {
        /* Drop packet in case of parsing error or SSRC different from the one expected. */
        /* This might happen at the very beginning of the communication or early after */
        /* a re-negotation has been concluded. */
        return;
    }
#endif
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
        LLOG(LL_TRACE, "stop timer id=%d", handle->rtcp_timer);
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
    //LLOG(LL_TRACE, "%p rtcp pkt len=%d", agent, size);
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
        LLOG(LL_ERROR, "ice_component_send failed, no valid candidate pair.");
        return -1;
    }
    struct sockaddr *addr = (struct sockaddr*)&agent->peer_addr;
    socklen_t slen = sizeof(struct sockaddr_in);
    if (agent->peer_tcp) {
        if (tcp_chan_get_write_buf_size(agent->peer_tcp) > ICE_MAX_TCP_WRITE_BUF_SIZE) {
            LLOG(LL_ERROR, "slow connection, abort stun-tcp channel.");
            ice_tcp_error_cleanup(agent->peer_tcp, agent->srv);
            return -1;
        }
        uint8_t frame_hdr[2];
        frame_hdr[0] = (size & 0xff00) >> 8;
        frame_hdr[1] = (size & 0xff);
        tcp_chan_write(agent->peer_tcp, frame_hdr, 2);
        tcp_chan_write(agent->peer_tcp, data, size);
        return size;
    } else {
        return udp_chan_write(agent->srv->udp_chan, data, size, addr, slen);
    }
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
    LLOG(LL_TRACE, "start timer id=%d", agent->rtcp_timer);

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
    if (!data || size < 1)
        return;
    ice_queued_packet *pkt = malloc(sizeof(ice_queued_packet));
    pkt->data = malloc(size + SRTP_MAX_TAG_LEN);
    memcpy(pkt->data, data, size);
    pkt->length = size;
    pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
    pkt->control = 0;
    pkt->encrypted = 0;
    pkt->retransmission = 0;
    pkt->added = zl_hrtimestamp();

    ice_send_packet(agent, pkt);
}

void send_rtcp(ice_agent_t *agent, int video, const void *data, int size)
{
    //return;
    if (!data || size < 1)
        return;
    ice_queued_packet *pkt = malloc(sizeof(ice_queued_packet));
    pkt->data = malloc(size + SRTP_MAX_TAG_LEN + 4);
    memcpy(pkt->data, data, size);
    pkt->length = size;
    pkt->type = video ? JANUS_ICE_PACKET_VIDEO : JANUS_ICE_PACKET_AUDIO;
    pkt->control = 1;
    pkt->encrypted = 0;
    pkt->retransmission = 0;
    pkt->added = zl_hrtimestamp();

    ice_send_packet(agent, pkt);
}

void ice_send_packet(ice_agent_t *agent, ice_queued_packet *pkt)
{
    struct sockaddr *dest_addr = (struct sockaddr*)&agent->peer_addr;
    socklen_t dest_addrlen = sizeof(struct sockaddr_in);
    ice_stream_t *stream = agent->stream;
    ice_component_t *component = stream->component;
    if (pkt->control) {
        /* RTCP */
        int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
        //stream->noerrorlog = FALSE;
        if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
            if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_ALERT)/* && !component->noerrorlog*/) {
                LLOG(LL_WARN, "%s stream component has no valid SRTP session (yet?)",
                     video ? "video" : "audio");
                //component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
            }
            ice_free_queued_packet(pkt);
            return;
        }
        //component->noerrorlog = FALSE;
        if (pkt->encrypted) {
            /* Already SRTCP */
            //int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
            //if (sent < pkt->length) {
            //    JANUS_LOG(LL_ERROR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
            //}
            int sent = ice_component_send(component, pkt->data, pkt->length);
            if (sent < pkt->length) {
                LLOG(LL_ERROR, " ... only sent %d bytes? (was %d)", sent, pkt->length);
            }
        } else {
        #if 0
            /* Check if there's anything we need to do before sending */
            uint32_t bitrate = janus_rtcp_get_remb(pkt->data, pkt->length);
            if (bitrate > 0) {
                /* There's a REMB, prepend a RR as it won't work otherwise */
                int rrlen = 32;
                char *rtcpbuf = malloc(rrlen + pkt->length + SRTP_MAX_TAG_LEN + 4);
                memset(rtcpbuf, 0, rrlen + pkt->length + SRTP_MAX_TAG_LEN + 4);
                rtcp_rr *rr = (rtcp_rr *)rtcpbuf;
                rr->header.version = 2;
                rr->header.type = RTCP_RR;
                rr->header.rc = 0;
                rr->header.length = htons((rrlen / 4) - 1);
                janus_ice_stream *stream = handle->stream;
                if (stream && stream->video_rtcp_ctx[0] && stream->video_rtcp_ctx[0]->rtp_recvd) {
                    rr->header.rc = 1;
                    janus_rtcp_report_block(stream->video_rtcp_ctx[0], &rr->rb[0]);
                }
                /* Append REMB */
                memcpy(rtcpbuf + rrlen, pkt->data, pkt->length);
                /* If we're simulcasting, set the extra SSRCs (the first one will be set by janus_rtcp_fix_ssrc) */
                if (stream->video_ssrc_peer[1] && pkt->length >= 28) {
                    rtcp_fb *rtcpfb = (rtcp_fb *)(rtcpbuf + rrlen);
                    rtcp_remb *remb = (rtcp_remb *)rtcpfb->fci;
                    remb->ssrc[1] = htonl(stream->video_ssrc_peer[1]);
                    if (stream->video_ssrc_peer[2] && pkt->length >= 32) {
                        remb->ssrc[2] = htonl(stream->video_ssrc_peer[2]);
                    }
                }
                /* Free old packet and update */
                char *prev_data = pkt->data;
                pkt->data = rtcpbuf;
                pkt->length = rrlen + pkt->length;
                g_clear_pointer(&prev_data, g_free);
            }
            /* Do we need to dump this packet for debugging? */
            if (g_atomic_int_get(&handle->dump_packets))
                janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTCP, FALSE, pkt->data, pkt->length,
                                     "[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
        #endif
            /* Encrypt SRTCP */
            int protected = pkt->length;
            int res = srtp_protect_rtcp(component->dtls->srtp_out, pkt->data, &protected);
            //LLOG(LL_TRACE, "encrypt %d -> %d", pkt->length, protected);
            if (res != srtp_err_status_ok) {
                /* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
                //handle->srtp_errors_count++;
                //handle->last_srtp_error = res;
                /* If we're debugging, though, print every occurrence */
                //JANUS_LOG(LL_DEBUG, "[%"SCNu64"] ... SRTCP protect error... %s (len=%d-->%d)...\n", handle->handle_id, janus_srtp_error_str(res), pkt->length, protected);
            } else {
                /* Shoot! */
                int sent = ice_component_send(component, pkt->data, protected);
                if (sent < protected) {
                    LLOG(LL_ERROR, " ... only sent %d bytes? (was %d)", sent, protected);
                }
            }
        }
        ice_free_queued_packet(pkt);
    } else {
        /* RTP or data */
        if (pkt->type == JANUS_ICE_PACKET_AUDIO || pkt->type == JANUS_ICE_PACKET_VIDEO) {
            /* RTP */
            int video = (pkt->type == JANUS_ICE_PACKET_VIDEO);
        #if 0
            if ((!video && !stream->audio_send) || (video && !stream->video_send)) {
                ice_free_queued_packet(pkt);
                return;
            }
        #endif
            if (!component->dtls || !component->dtls->srtp_valid || !component->dtls->srtp_out) {
                if (!ice_flags_is_set(agent, ICE_HANDLE_WEBRTC_ALERT)/* && !component->noerrorlog*/) {
                    //LLOG(LL_WARN, "%s stream component has no valid SRTP session (yet?)",
                    //     video ? "video" : "audio");
                    //component->noerrorlog = TRUE;	/* Don't flood with the same error all over again */
                }
                ice_free_queued_packet(pkt);
                return;
            }
            //component->noerrorlog = FALSE;
            if (pkt->encrypted) {
                /* Already RTP (probably a retransmission?) */
                rtp_header *header = (rtp_header *)pkt->data;
                LLOG(LL_WARN, " ... Retransmitting seq.nr %"SCNu16, ntohs(header->seq_number));
            #if 0
                int sent = nice_agent_send(handle->agent, stream->stream_id, component->component_id, pkt->length, (const gchar *)pkt->data);
                if (sent < pkt->length) {
                    JANUS_LOG(LL_ERROR, "[%"SCNu64"] ... only sent %d bytes? (was %d)\n", handle->handle_id, sent, pkt->length);
                }
            #endif
            } else {
                /* Overwrite SSRC */
                rtp_header *header = (rtp_header *)pkt->data;
                if (!pkt->retransmission) {
                    /* ... but only if this isn't a retransmission (for those we already set it before) */
                    header->ssrc = htonl(video ? stream->video_ssrc : stream->audio_ssrc);
                }
            #if 0
                /* Keep track of payload types too */
                if (!video && stream->audio_payload_type < 0) {
                    stream->audio_payload_type = header->type;
                    if (stream->audio_codec == NULL) {
                        const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->audio_payload_type);
                        if (codec != NULL)
                            stream->audio_codec = g_strdup(codec);
                    }
                } else if (video && stream->video_payload_type < 0) {
                    stream->video_payload_type = header->type;
                    if (ice_flags_is_set(agent, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX) &&
                        stream->rtx_payload_types && g_hash_table_size(stream->rtx_payload_types) > 0) {
                        stream->video_rtx_payload_type = GPOINTER_TO_INT(g_hash_table_lookup(stream->rtx_payload_types, GINT_TO_POINTER(stream->video_payload_type)));
                        JANUS_LOG(LL_TRACE, "[%"SCNu64"] Retransmissions will have payload type %d\n",
                                  handle->handle_id, stream->video_rtx_payload_type);
                    }
                    if (stream->video_codec == NULL) {
                        const char *codec = janus_get_codec_from_pt(handle->local_sdp, stream->video_payload_type);
                        if (codec != NULL)
                            stream->video_codec = g_strdup(codec);
                    }
                    if (stream->video_is_keyframe == NULL && stream->video_codec != NULL) {
                        if (!strcasecmp(stream->video_codec, "vp8"))
                            stream->video_is_keyframe = &janus_vp8_is_keyframe;
                        else if (!strcasecmp(stream->video_codec, "vp9"))
                            stream->video_is_keyframe = &janus_vp9_is_keyframe;
                        else if (!strcasecmp(stream->video_codec, "h264"))
                            stream->video_is_keyframe = &janus_h264_is_keyframe;
                    }
                }
            #endif
            #if 0
                /* Do we need to dump this packet for debugging? */
                if (g_atomic_int_get(&handle->dump_packets))
                    janus_text2pcap_dump(handle->text2pcap, JANUS_TEXT2PCAP_RTP, FALSE, pkt->data, pkt->length,
                                         "[session=%"SCNu64"][handle=%"SCNu64"]", session->session_id, handle->handle_id);
                                 /* If this is video, check if this is a keyframe: if so, we empty our retransmit buffer for incoming NACKs */
                if (video && stream->video_is_keyframe) {
                    int plen = 0;
                    char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
                    if (stream->video_is_keyframe(payload, plen)) {
                        JANUS_LOG(LL_TRACE, "[%"SCNu64"] Keyframe sent, cleaning retransmit buffer\n", handle->handle_id);
                        janus_cleanup_nack_buffer(0, stream, FALSE, TRUE);
                    }
                }
            #endif
            #if 0
                /* Before encrypting, check if we need to copy the unencrypted payload (e.g., for rtx/90000) */
                janus_rtp_packet *p = NULL;
                if (max_nack_queue > 0 && !pkt->retransmission && pkt->type == JANUS_ICE_PACKET_VIDEO && component->do_video_nacks &&
                    ice_flags_is_set(agent, JANUS_ICE_HANDLE_WEBRTC_RFC4588_RTX)) {
                /* Save the packet for retransmissions that may be needed later: start by
                 * making room for two more bytes to store the original sequence number */
                    p = g_malloc(sizeof(janus_rtp_packet));
                    janus_rtp_header *header = (janus_rtp_header *)pkt->data;
                    uint16_t original_seq = header->seq_number;
                    p->data = g_malloc(pkt->length + 2);
                    p->length = pkt->length + 2;
                    /* Check where the payload starts */
                    int plen = 0;
                    char *payload = janus_rtp_payload(pkt->data, pkt->length, &plen);
                    size_t hsize = payload - pkt->data;
                    /* Copy the header first */
                    memcpy(p->data, pkt->data, hsize);
                    /* Copy the original sequence number */
                    memcpy(p->data + hsize, &original_seq, 2);
                    /* Copy the payload */
                    memcpy(p->data + hsize + 2, payload, pkt->length - hsize);
                }
            #endif
                /* Encrypt SRTP */
                int protected = pkt->length;
                int res = srtp_protect(component->dtls->srtp_out, pkt->data, &protected);
                if (res != srtp_err_status_ok) {
                #if 0
                    /* We don't spam the logs for every SRTP error: just take note of this, and print a summary later */
                    handle->srtp_errors_count++;
                    handle->last_srtp_error = res;
                #endif
                    /* If we're debugging, though, print every occurrence */
                    rtp_header *header = (rtp_header *)pkt->data;
                    uint32_t timestamp = ntohl(header->timestamp);
                    uint16_t seq = ntohs(header->seq_number);
                    LLOG(LL_DEBUG, " ... SRTP protect error... %s (len=%d-->%d, ts=%"SCNu32", seq=%"SCNu16")...",
                         rtz_srtp_error_str(res), pkt->length, protected, timestamp, seq);
                #if 0
                    janus_ice_free_rtp_packet(p);
                #endif
                } else {
                    rtp_header *hdr = (rtp_header*)pkt->data;
                    //LLOG(LL_TRACE, "send m=%d ts=%d size=%d", (int)hdr->markerbit, ntohl(hdr->timestamp), protected);
                    /* Shoot! */
                    int sent = ice_component_send(component, pkt->data, protected);
                    if (sent < protected) {
                        LLOG(LL_ERROR, " ... only sent %d bytes? (was %d), err: %s", sent, protected, strerror(errno));
                    }
                    /* Update stats */
                    if (sent > 0) {
                        /* Update the RTCP context as well */
                        rtp_header *header = (rtp_header *)pkt->data;
                        uint32_t timestamp = ntohl(header->timestamp);
                        if (pkt->type == JANUS_ICE_PACKET_AUDIO) {
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
                        } else if (pkt->type == JANUS_ICE_PACKET_VIDEO) {
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
                        }
                        /* Update sent packets counter */
                        rtcp_context *rtcp_ctx = video ? stream->video_rtcp_ctx : stream->audio_rtcp_ctx;
                        ++rtcp_ctx->sent_packets_since_last_rr;
                    }
                #if 0
                    if (max_nack_queue > 0 && !pkt->retransmission) {
                        /* Save the packet for retransmissions that may be needed later */
                        if ((pkt->type == JANUS_ICE_PACKET_AUDIO && !component->do_audio_nacks) ||
                            (pkt->type == JANUS_ICE_PACKET_VIDEO && !component->do_video_nacks)) {
                        /* ... unless NACKs are disabled for this medium */
                            ice_free_queued_packet(pkt);
                            return G_SOURCE_CONTINUE;
                        }
                        if (p == NULL) {
                            /* If we're not doing RFC4588, we're saving the SRTP packet as it is */
                            p = g_malloc(sizeof(janus_rtp_packet));
                            p->data = g_malloc(protected);
                            memcpy(p->data, pkt->data, protected);
                            p->length = protected;
                        }
                        p->created = janus_get_monotonic_time();
                        p->last_retransmit = 0;
                        janus_rtp_header *header = (janus_rtp_header *)pkt->data;
                        uint16_t seq = ntohs(header->seq_number);
                        if (!video) {
                            if (component->audio_retransmit_buffer == NULL) {
                                component->audio_retransmit_buffer = g_queue_new();
                                component->audio_retransmit_seqs = g_hash_table_new(NULL, NULL);
                            }
                            g_queue_push_tail(component->audio_retransmit_buffer, p);
                            /* Insert in the table too, for quick lookup */
                            g_hash_table_insert(component->audio_retransmit_seqs, GUINT_TO_POINTER(seq), p);
                        } else {
                            if (component->video_retransmit_buffer == NULL) {
                                component->video_retransmit_buffer = g_queue_new();
                                component->video_retransmit_seqs = g_hash_table_new(NULL, NULL);
                            }
                            g_queue_push_tail(component->video_retransmit_buffer, p);
                            /* Insert in the table too, for quick lookup */
                            g_hash_table_insert(component->video_retransmit_seqs, GUINT_TO_POINTER(seq), p);
                        }
                    } else {
                        janus_ice_free_rtp_packet(p);
                    }
                #endif
                }
            }
            ice_free_queued_packet(pkt);
        } else {
            LLOG(LL_WARN, "Unsupported packet type %d", pkt->type);
            ice_free_queued_packet(pkt);
        }
    }
}

void ice_free_queued_packet(ice_queued_packet *pkt)
{
    if (pkt == NULL) {
        return;
    }
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
        rtcp_sdes_cname((char *)sdes, sdeslen, "rtzvideo", 8);
        sdes->chunk.ssrc = htonl(stream->video_ssrc);
        send_rtcp(handle, 1, rtcpbuf, srlen + sdeslen);
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
        rtcp_sdes_cname((char *)sdes, sdeslen, "rtzaudio", 8);
        sdes->chunk.ssrc = htonl(stream->audio_ssrc);
        send_rtcp(handle, 0, rtcpbuf, srlen + sdeslen);
    }
#endif
}

void ice_tcp_error_cleanup(tcp_chan_t *chan, ice_server_t *srv)
{
    ice_agent_t *agent;
    list_for_each_entry(agent, &srv->agent_list, link) {
        if (agent->peer_tcp == chan) {
            agent->peer_tcp = NULL;
            agent->cand_state = ICE_CAND_STATE_EMPTY;
            ice_webrtc_hangup(agent, "TcpSocket Error");
        }
    }
    tcp_chan_close(chan, 0);
}

void ice_tcp_data_handler(tcp_chan_t *chan, void *udata)
{
    ice_server_t *srv = udata;
    uint8_t data[ICE_MAX_TCP_FRAME_SIZE];
    int qlen = tcp_chan_get_read_buf_size(chan);
    while (qlen >= 2) {
        uint8_t buf[2];
        tcp_chan_peek(chan, buf, 2);
        int size = (buf[0] << 8) | buf[1];
        if (size > ICE_MAX_TCP_FRAME_SIZE) {
            ice_tcp_error_cleanup(chan, srv);
            break;
        }
        if (qlen >= 2 + size) {
            tcp_chan_read(chan, buf, 2);
            tcp_chan_read(chan, data, size);
            struct sockaddr_in addr_in;
            struct sockaddr *addr = (struct sockaddr*)&addr_in;
            int addrlen = sizeof(struct sockaddr_in);
            tcp_chan_get_peername(chan, addr, addrlen);
            ice_agent_t *agent = find_agent_by_address(srv, addr, addrlen, 1);
            enum ice_payload_type type = get_payload_type(data, size);
            if (type == ICE_PAYLOAD_STUN) {
                stun_handler(srv, data, size, addr, addrlen, chan);
            } else if (type == ICE_PAYLOAD_DTLS) {
                dtls_handler(agent, data, size, addr, addrlen);
            } else if (type == ICE_PAYLOAD_RTP) {
                srtp_handler(agent, data, size);
            } else if (type == ICE_PAYLOAD_RTCP) {
                srtcp_handler(agent, data, size);
            } else {
                LLOG(LL_WARN, "unhandled muxed payload type=%d", type);
            }
        } else {
            break;
        }
        qlen = tcp_chan_get_read_buf_size(chan);
    }
}

void ice_tcp_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    ice_tcp_error_cleanup(chan, udata);
}
