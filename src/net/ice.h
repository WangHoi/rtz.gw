/** @file ice.h
 *  ICE-Lite implementation.
 *
 *  Contains prototypes for ICE agent.
 */
#pragma once
#include "sbuf.h"
#include <sys/socket.h>
#include <stdint.h>

enum {
    ICE_HANDLE_WEBRTC_READY = (1 << 2),
    ICE_HANDLE_WEBRTC_STOP = (1 << 3),
    ICE_HANDLE_WEBRTC_ALERT = (1 << 4),
    ICE_HANDLE_WEBRTC_CLEANING = (1 << 11),
    ICE_HANDLE_WEBRTC_HAS_AUDIO = (1 << 12),
    ICE_HANDLE_WEBRTC_HAS_VIDEO = (1 << 13),
    ICE_HANDLE_WEBRTC_GOT_OFFER = (1 << 14),
    ICE_HANDLE_WEBRTC_GOT_ANSWER = (1 << 15),
};

typedef struct zl_loop_t zl_loop_t;
typedef struct ice_component_t ice_component_t;
typedef struct ice_stream_t ice_stream_t;
typedef struct ice_agent_t ice_agent_t;
typedef struct ice_server_t ice_server_t;
typedef struct sbuf_t sbuf_t;

ice_server_t *ice_server_new(zl_loop_t *loop);
void ice_server_del(ice_server_t *srv);
void ice_server_bind(ice_server_t *srv, const char *ip,
                     unsigned short port);
void ice_server_start(ice_server_t *srv);

/** Create ICE agent.
 *  @return The ICE agent.
 */
ice_agent_t *ice_agent_new(ice_server_t *srv, void *rtz_handle);

/** Destroy ICE agent.
 *  @param agent The ICE agent.
 */
void ice_agent_del(ice_agent_t *agent);

/** Get local ICE username.
 *  @param agent The ICE agent.
 *  @return The ICE username.
 */
const char *ice_get_luser(ice_agent_t *agent);

/** Get local ICE password.
 *  @param agent The ICE agent.
 *  @return The ICE password.
 */
const char *ice_get_lpass(ice_agent_t *agent);

/** Get remote ICE username.
 *  @param agent The ICE agent.
 *  @return The ICE username.
 */
const char *ice_get_ruser(ice_agent_t *agent);

/** Get remote ICE password.
 *  @param agent The ICE agent.
 *  @return The ICE password.
 */
sbuf_t *ice_get_rpass(ice_agent_t *agent);

/** Generate the local candidate attribute.
 *  @param agent The ICE agent.
 *  @param b The candidate attribute line, eg:
 *      "candidate <foundation> <component> <proto> <priority> <ip> <port> typ host"
 */
//void ice_get_local_candiate(ice_agent_t *agent, sbuf_t *b);

uint32_t ice_get_ssrc(ice_agent_t *agent, int video);

void ice_webrtc_hangup(ice_agent_t *handle, const char *reason);

ice_stream_t *ice_get_stream(ice_agent_t *agent);

ice_stream_t *ice_component_get_stream(ice_component_t *component);

int ice_component_send(ice_component_t *component, const void *data, int size);

ice_agent_t *ice_stream_get_agent(ice_stream_t *stream);

sbuf_t *ice_stream_get_remote_hashing(ice_stream_t *stream);

sbuf_t *ice_stream_get_remote_fingerprint(ice_stream_t *stream);

void ice_dtls_handshake_done(ice_agent_t *agent, ice_component_t *component);

void ice_flags_reset(ice_agent_t *agent);

void ice_flags_set(ice_agent_t *agent, unsigned flag);

void ice_flags_clear(ice_agent_t *agent, unsigned flag);

int ice_flags_is_set(ice_agent_t *agent, unsigned flag);

void ice_send_rtp(ice_agent_t *agent, int video, const void *data, int size);
