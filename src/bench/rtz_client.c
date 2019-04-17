#include "rtz_client.h"
#include "sbuf.h"
#include "event_loop.h"
#include "net/tcp_chan.h"
#include "net/tcp_simple_writer.h"
#include "net/http_types.h"
#include "net/rtp.h"
#include "net/dtls.h"
#include "net/stun.h"
#include "net/ice.h"
#include "net/rtp_srtp.h"
#include "net/rtcp.h"
#include "net/rtp.h"
#include "net/rtp_srtp.h"
#include "pack_util.h"
#include "log.h"
#include <stdlib.h>
#include <string.h>
#include <cJSON.h>
#include <inttypes.h>
#include <assert.h>

enum {
    RTZ_CLIENT_CONNECTED = 1,
    RTZ_CLIENT_UPGRADED = 2,
    RTZ_CLIENT_READY = 4,
    RTZ_CLIENT_MEDIA_CONNECTED = 8,
    RTZ_CLIENT_ERROR = 16,
};

struct rtz_client_t {
    int flag;
    zl_loop_t *loop;
    tcp_chan_t *chan;
    tcp_simple_writer_t *chan_writer;
    sbuf_t *rcv_buf;
    tcp_chan_t *media_chan;
    tcp_simple_writer_t *media_chan_writer;
    sbuf_t *media_rcv_buf;

    sbuf_t *session_id;
    sbuf_t *handle_id;
    sbuf_t *url;

    sbuf_t *ice_luser;
    sbuf_t *ice_lpwd;
    sbuf_t *ice_rip;
    int ice_rport;
    sbuf_t *ice_ruser;
    sbuf_t *ice_rpwd;
    uint32_t audio_ssrc;
    uint32_t video_ssrc;
    int sdp_version;
    int stun_timer;
    int rtcp_timer;
    sbuf_t *rhash;
    sbuf_t *rfingerprint;

    int srtp_valid;
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
    dtls_state dtls_state;
    /** The SRTP profile currently in use */
    int srtp_profile;
    /** libsrtp context for incoming SRTP packets */
    srtp_t srtp_in;
    /** libsrtp context for outgoing SRTP packets */
    srtp_t srtp_out;
    /** libsrtp policy for incoming SRTP packets */
    srtp_policy_t remote_policy;
    /** libsrtp policy for outgoing SRTP packets */
    srtp_policy_t local_policy;

    long recv_bytes;
    long send_bytes;
};

static void rtz_client_sent_handler(tcp_chan_t *chan, void *udata);
static void rtz_client_data_handler(tcp_chan_t *chan, void *udata);
static void rtz_client_event_handler(tcp_chan_t *chan, int status, void *udata);
static void rtz_media_sent_handler(tcp_chan_t *chan, void *udata);
static void rtz_media_data_handler(tcp_chan_t *chan, void *udata);
static void rtz_media_event_handler(tcp_chan_t *chan, int status, void *udata);
static void send_ws_frame(rtz_client_t *client, int opcode, const void *data, int size);
static void send_json(rtz_client_t *client, cJSON *json);
static void send_create_session(rtz_client_t *client);
static void send_create_handle(rtz_client_t *client);
static void send_sdp_answer(rtz_client_t *client, const char *sdp);
static void client_ws_frame_handler(rtz_client_t *client, struct ws_frame *frame);
void handle_event(rtz_client_t *client, const char *transaction,
                  const char *session_id, const char *handle_id,
                  const char *status, const char *jsep);
static sbuf_t *create_sdp(rtz_client_t *client, int tcp);
static void process_sdp_offer(rtz_client_t *client, const char *sdp_offer);
static void send_media_data(rtz_client_t *client, const void *data, int size);
static void rtz_client_stun_timeout_handler(zl_loop_t *loop, int timer, void *udata);
static void rtz_client_rtcp_timeout_handler(zl_loop_t *loop, int timer, void *udata);
static void dtls_handler(rtz_client_t *client, const void *data, int size);
static void rtz_client_srtp_create(rtz_client_t *client);

rtz_client_t *rtz_client_new(zl_loop_t *loop)
{
    rtz_client_t *client = malloc(sizeof(rtz_client_t));
    memset(client, 0, sizeof(rtz_client_t));
    client->loop = loop;
    client->rcv_buf = sbuf_new1(65537);
    client->session_id = sbuf_new1(64);
    client->handle_id = sbuf_new1(64);
    client->url = sbuf_new1(1024);
    client->ice_luser = sbuf_random_string(4);
    client->ice_lpwd = sbuf_random_string(12);
    client->ice_ruser = sbuf_new1(5);
    client->ice_rpwd = sbuf_new1(32);
    client->ice_rip = sbuf_new1(16);
    client->media_rcv_buf = sbuf_new1(65537);
    client->rhash = sbuf_new();
    client->rfingerprint = sbuf_new();
    client->stun_timer = -1;
    client->rtcp_timer = -1;
    return client;
}

void rtz_client_del(rtz_client_t *client)
{
    LLOG(LL_TRACE, "del client %p recv_bytes=%ld send_bytes=%ld",
         client, client->recv_bytes, client->send_bytes);
    if (!client)
        return;
    if (client->chan_writer)
        tcp_simple_writer_del(client->chan_writer);
    if (client->chan)
        tcp_chan_close(client->chan, 0);
    if (client->media_chan_writer)
        tcp_simple_writer_del(client->media_chan_writer);
    if (client->media_chan)
        tcp_chan_close(client->media_chan, 0);
    if (client->stun_timer != -1)
        zl_timer_stop(client->loop, client->stun_timer);
    if (client->rtcp_timer != -1)
        zl_timer_stop(client->loop, client->rtcp_timer);
    sbuf_del(client->media_rcv_buf);
    sbuf_del(client->rcv_buf);
    sbuf_del(client->session_id);
    sbuf_del(client->handle_id);
    sbuf_del(client->url);
    sbuf_del(client->ice_luser);
    sbuf_del(client->ice_lpwd);
    sbuf_del(client->ice_ruser);
    sbuf_del(client->ice_rpwd);
    sbuf_del(client->ice_rip);
    sbuf_del(client->rhash);
    sbuf_del(client->rfingerprint);
    if (client->ssl != NULL) {
        SSL_free(client->ssl);
        client->ssl = NULL;
    }
    /* BIOs are destroyed by SSL_free */
    client->read_bio = NULL;
    client->write_bio = NULL;
    if (client->srtp_valid) {
        if (client->srtp_in) {
            srtp_dealloc(client->srtp_in);
            client->srtp_in = NULL;
        }
        if (client->srtp_out) {
            srtp_dealloc(client->srtp_out);
            client->srtp_out = NULL;
        }
    }
    free(client);
}

void rtz_client_open(rtz_client_t *client, const char *ip, int port)
{
    client->chan = tcp_connect(client->loop, ip, port);
    tcp_chan_set_cb(client->chan, rtz_client_data_handler, rtz_client_sent_handler, rtz_client_event_handler, client);
}

void rtz_client_play(rtz_client_t *client, const char *url)
{
    sbuf_strcpy(client->url, url);
}

void rtz_client_close(rtz_client_t *client)
{
    if (client->chan)
        tcp_chan_close(client->chan, 0);
    client->chan = NULL;
    if (client->media_chan)
        tcp_chan_close(client->media_chan, 0);
    client->media_chan = NULL;
    client->flag = 0;
}

void rtz_client_data_handler(tcp_chan_t *chan, void *udata)
{
    rtz_client_t *client = udata;
    while (!(client->flag & RTZ_CLIENT_ERROR) && !tcp_chan_read_buf_empty(chan)) {
        if (client->flag & RTZ_CLIENT_UPGRADED) {
            struct ws_frame frame;
            int i, expect_size = 0;
            if (client->rcv_buf->size < 2) {
                sbuf_appendc(client->rcv_buf, tcp_chan_readc(chan));
            } else {
                char *p = client->rcv_buf->data;
                frame.fin = p[0] & 0x80;
                frame.opcode = p[0] & 0xf;
                frame.mask = p[1] & 0x80;
                frame.payload_len = p[1] & 0x7f;

                if (frame.payload_len == 126) {
                    if (client->rcv_buf->size < 4) {
                        sbuf_appendc(client->rcv_buf, tcp_chan_readc(chan));
                        continue;
                    } else {
                        frame.payload_len = unpack_be16(client->rcv_buf->data + 2);
                        expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 4 - client->rcv_buf->size;
                    }
                } else if (frame.payload_len == 127) {
                    if (client->rcv_buf->size < 10) {
                        sbuf_appendc(client->rcv_buf, tcp_chan_readc(chan));
                        continue;
                    } else {
                        frame.payload_len = (int)unpack_be64(client->rcv_buf->data + 2);
                        expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 10 - client->rcv_buf->size;
                    }
                } else {
                    expect_size = frame.payload_len + (frame.mask ? 4 : 0) + 2 - client->rcv_buf->size;
                }

                int old_size = client->rcv_buf->size;
                int buf_size = tcp_chan_get_read_buf_size(chan);
                if (buf_size < expect_size) {
                    sbuf_resize(client->rcv_buf, old_size + buf_size);
                    tcp_chan_read(chan, client->rcv_buf->data + old_size, buf_size);
                    break;
                }

                sbuf_resize(client->rcv_buf, old_size + expect_size);
                tcp_chan_read(chan, client->rcv_buf->data + old_size, expect_size);
                frame.payload_data = sbuf_tail(client->rcv_buf) - frame.payload_len;
                if (frame.mask) {
                    memcpy(frame.mask_key, sbuf_tail(client->rcv_buf) - frame.payload_len - 4, 4);
                    int i;
                    for (i = 0; i < frame.payload_len; ++i)
                        frame.payload_data[i] ^= frame.mask_key[i % 4];
                }
                client_ws_frame_handler(client, &frame);
                sbuf_clear(client->rcv_buf);
            }
        } else {
            char c = tcp_chan_readc(chan);
            sbuf_appendc(client->rcv_buf, c);
            if (sbuf_ends_with(client->rcv_buf, "\r\n\r\n")) {
                http_response_t *r;
                r = http_parse_response(client, client->rcv_buf->data, sbuf_tail(client->rcv_buf));
                if (r && r->status == HTTP_STATUS_SWITCHING_PROTOCOLS) {
                    client->flag |= RTZ_CLIENT_UPGRADED;
                    send_create_session(client);
                } else {
                    client->flag |= RTZ_CLIENT_ERROR;
                }
                sbuf_clear(client->rcv_buf);
                if (r)
                    http_response_del(r);
            }
        }
    }
}

void rtz_client_sent_handler(tcp_chan_t *chan, void *udata)
{
    rtz_client_t *client = udata;
    tcp_simple_writer_sent_notify(client->chan_writer);
}

void rtz_client_event_handler(tcp_chan_t *chan, int status, void *udata)
{
    rtz_client_t *client = udata;
    if (status > 0) {
        LLOG(LL_TRACE, "client %p connected", udata);
        client->chan_writer = tcp_simple_writer_new(chan);
        client->flag = RTZ_CLIENT_CONNECTED;
        sbuf_t *b = sbuf_new1(1024);
        sbuf_printf(b, "GET /rtz HTTP/1.1\r\n"
                    "Sec-WebSocket-Key:abc\r\n\r\n");
        tcp_simple_writer_perform(client->chan_writer, b->data, b->size);
        sbuf_del(b);
    } else {
        LLOG(LL_ERROR, "%p socket event %d", udata, status);
        client->flag = RTZ_CLIENT_ERROR;
    }
}

void send_ws_frame(rtz_client_t *client, int opcode, const void *data, int size)
{
    if (client->flag & RTZ_CLIENT_ERROR)
        return;
    if (!(client->flag & RTZ_CLIENT_UPGRADED))
        return;

    char header[10];
    int n = 0;
    header[0] = 0x80 | (char)opcode;
    if (size > 65535) {
        header[1] = 127;
        pack_be64(&header[2], size);
        n = 10;
    } else if (size > 125) {
        header[1] = 126;
        pack_be16(&header[2], size);
        n = 4;
    } else {
        header[1] = size;
        n = 2;
    }
    struct iovec iov[2] = {
        { header, n },
        { (void*)data, size },
    };
    tcp_simple_writer_performv(client->chan_writer, iov, 2);
}

void send_json(rtz_client_t *client, cJSON *json)
{
    if (client->flag & RTZ_CLIENT_ERROR)
        return;
    char *text = cJSON_PrintUnformatted(json);
    if (!text)
        return;
    send_ws_frame(client, WS_OPCODE_TEXT, text, strlen(text));
    free(text);
}

void send_create_session(rtz_client_t *client)
{
    sbuf_t *txid = sbuf_random_string(12);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "createSession");
    cJSON_AddStringToObject(json, "transaction", txid->data);
    send_json(client, json);
    cJSON_Delete(json);
    sbuf_del(txid);
}

void send_create_handle(rtz_client_t *client)
{
    sbuf_t *txid = sbuf_random_string(12);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "createHandle");
    cJSON_AddStringToObject(json, "transaction", txid->data);
    cJSON_AddStringToObject(json, "session_id", client->session_id->data);
    cJSON_AddStringToObject(json, "url", client->url->data);
    cJSON_AddStringToObject(json, "transport", "tcp");
    cJSON_AddNumberToObject(json, "min_delay", 8);
    send_json(client, json);
    cJSON_Delete(json);
    sbuf_del(txid);
}

void client_ws_frame_handler(rtz_client_t *client, struct ws_frame *frame)
{
    //LLOG(LL_TRACE, "got ws_frame fin=%hhu opcode=%hhu mask=%hhu payload_len=%d",
    //     frame->fin, frame->opcode, frame->mask, frame->payload_len);
    if (frame->opcode == WS_OPCODE_CLOSE) {
        //client->flag |= HTTP_PEER_CLOSE_ASAP;
    } else if (frame->opcode == WS_OPCODE_PING) {
        send_ws_frame(client, WS_OPCODE_PONG, frame->payload_data, frame->payload_len);
    } else if (frame->opcode == WS_OPCODE_TEXT) {
        //LLOG(LL_TRACE, "payload='%s'", strndup(frame->payload_data, frame->payload_len));
        cJSON *json = cJSON_ParseWithOpts(frame->payload_data, NULL, cJSON_False);
        const char *type = cJSON_GetStringValue(cJSON_GetObjectItem(json, "type"));
        const char *transaction = cJSON_GetStringValue(cJSON_GetObjectItem(json, "transaction"));
        const char *session_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "session_id"));
        if (type && transaction) {
            if (!strcmp(type, "success")) {
                if (!(client->flag & RTZ_CLIENT_READY)) {
                    sbuf_strcpy(client->session_id, session_id);
                    client->flag |= RTZ_CLIENT_READY;
                    send_create_handle(client);
                }
            } else if (!strcmp(type, "event")) {
                const char *handle_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "sender"));
                const char *status = cJSON_GetStringValue(cJSON_GetObjectItem(
                    cJSON_GetObjectItem(cJSON_GetObjectItem(json, "data"), "result"),
                    "status"));
                const char *sdp = cJSON_GetStringValue(cJSON_GetObjectItem(
                    cJSON_GetObjectItem(json, "jsep"), "sdp"));
                handle_event(client, transaction, session_id, handle_id, status, sdp);
            } else if (!strcmp(type, "message")) {
                const char *handle_id = cJSON_GetStringValue(cJSON_GetObjectItem(json, "handle_id"));
                cJSON *body = cJSON_GetObjectItem(json, "body");
                cJSON *jsep = cJSON_GetObjectItem(json, "jsep");
                //handle_message(client, transaction, session_id, handle_id, body, jsep);
            } else {
                char *body = strndup(frame->payload_data, frame->payload_len);
                if (body) {
                    LLOG(LL_WARN, "unhandled type='%s' body='%s'", type, body);
                    free(body);
                }
            }
        }
        cJSON_Delete(json);
    }
}

void handle_event(rtz_client_t *client, const char *transaction,
                  const char *session_id, const char *handle_id,
                  const char *status, const char *sdp_offer)
{
    if (!strcasecmp(status, "preparing")) {
        sbuf_strcpy(client->handle_id, handle_id);
        process_sdp_offer(client, sdp_offer);
        client->media_chan = tcp_connect(client->loop, client->ice_rip->data, client->ice_rport);
        tcp_chan_set_cb(client->media_chan, rtz_media_data_handler, rtz_media_sent_handler,
                        rtz_media_event_handler, client);
        sbuf_t *sdp_answer = create_sdp(client, 1);
        send_sdp_answer(client, sdp_answer->data);
        sbuf_del(sdp_answer);
    }
}

sbuf_t *create_sdp(rtz_client_t *client, int tcp)
{
    const char *fingerprint = dtls_get_local_fingerprint();
    sbuf_t *sdp = sbuf_newf(
        "v=0\r\n"
        "o=- 1550110455648463 %d IN IP4 127.0.0.1\r\n"
        "s=-\r\n"
        "t=0 0\r\n"
        "a=group:BUNDLE audio video\r\n"
        "a=msid-semantic: WMS rtz\r\n"
        "a=ice-lite\r\n",
        ++client->sdp_version);

    sbuf_appendf(
        sdp,
        "m=audio 9 UDP/TLS/RTP/SAVPF 8\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=recvonly\r\n"
        "a=mid:audio\r\n"
        "a=rtcp-mux\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:active\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
        //"a=maxptime:40\r\n"
        "a=fmtp:8 \r\n",
        client->ice_luser->data, client->ice_lpwd->data, fingerprint);

    sbuf_appendf(
        sdp,
        "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
        "c=IN IP4 0.0.0.0\r\n"
        "a=recvonly\r\n"
        "a=mid:video\r\n"
        "a=rtcp-mux\r\n"
        "a=ice-ufrag:%s\r\n"
        "a=ice-pwd:%s\r\n"
        "a=ice-options:trickle\r\n"
        "a=fingerprint:sha-256 %s\r\n"
        "a=setup:active\r\n"
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1\r\n"
        "a=rtcp-fb:96 nack\r\n"
        "a=rtcp-fb:96 nack pli\r\n"
        "a=rtcp-fb:96 goog-remb\r\n",
        client->ice_luser->data, client->ice_lpwd->data, fingerprint);
    sbuf_appendf(
        sdp,
        "a=extmap:6 %s\r\n",
        RTZ_RTP_EXTMAP_PLAYOUT_DELAY);

    return sdp;
}

void send_sdp_answer(rtz_client_t *client, const char *sdp)
{
    sbuf_t *txid = sbuf_random_string(12);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", "message");
    cJSON_AddStringToObject(json, "transaction", txid->data);
    cJSON_AddStringToObject(json, "session_id", client->session_id->data);
    cJSON_AddStringToObject(json, "handle_id", client->handle_id->data);
    {
        cJSON *body = cJSON_AddObjectToObject(json, "body");
        cJSON_AddStringToObject(body, "request", "start");
    }
    {
        cJSON *jsep = cJSON_AddObjectToObject(json, "jsep");
        cJSON_AddStringToObject(jsep, "type", "answer");
        cJSON_AddStringToObject(jsep, "sdp", sdp);
    }
    send_json(client, json);
    cJSON_Delete(json);
    sbuf_del(txid);
}

void process_sdp_offer(rtz_client_t *client, const char *sdp)
{
    const char *p;
    char *ice_ruser, *ice_rpwd, *ice_transport, *ice_rip;
    int ret;
    p = strstr(sdp, "a=ice-ufrag:");
    assert(p);
    ret = sscanf(p, "a=ice-ufrag: %ms", &ice_ruser);
    assert(ret == 1);
    p = strstr(sdp, "a=ice-pwd:");
    assert(p);
    ret = sscanf(p, "a=ice-pwd: %ms", &ice_rpwd);
    assert(ret == 1);
    sbuf_strcpy(client->ice_ruser, ice_ruser);
    sbuf_strcpy(client->ice_rpwd, ice_rpwd);
    p = strstr(sdp, "a=candidate:");
    assert(p);
    ret = sscanf(p, "a=candidate: %*d %*d %ms %*d %ms %d", &ice_transport, &ice_rip, &client->ice_rport);
    assert(ret == 3);
    sbuf_strcpy(client->ice_rip, ice_rip);

    p = strstr(sdp, "m=audio");
    if (p) {
        p = strstr(p, "a=ssrc:");
        assert(p);
        sscanf(p, "a=ssrc: %"SCNu32, &client->audio_ssrc);
    }

    p = strstr(sdp, "m=video");
    if (p) {
        p = strstr(p, "a=ssrc:");
        assert(p);
        sscanf(p, "a=ssrc: %"SCNu32, &client->video_ssrc);
    }

    //LLOG(LL_TRACE, "client %p ruser=%s rpwd=%s cand:%s %s:%d ssrc a=%u v=%u",
    //     client, ice_ruser, ice_rpwd,
    //     ice_transport, ice_rip, client->ice_rport, client->audio_ssrc, client->video_ssrc);

    free(ice_ruser);
    free(ice_rpwd);
    free(ice_transport);
    free(ice_rip);
}

void rtz_media_sent_handler(tcp_chan_t *chan, void *udata)
{
    rtz_client_t *client = udata;
    tcp_simple_writer_sent_notify(client->media_chan_writer);
}

void rtz_media_data_handler(tcp_chan_t *chan, void *udata)
{
    rtz_client_t *client = udata;
    uint8_t hdr[2];
    while (!(client->flag & RTZ_CLIENT_ERROR) && !tcp_chan_read_buf_empty(chan)) {
        int qlen = tcp_chan_get_read_buf_size(chan);
        if (qlen < 2)
            break;
        tcp_chan_peek(chan, hdr, 2);
        int len = (hdr[0] << 8) | hdr[1];
        if (qlen < 2 + len)
            break;
        tcp_chan_read(chan, hdr, 2);
        sbuf_clear(client->media_rcv_buf);
        sbuf_resize(client->media_rcv_buf, len);
        tcp_chan_read(chan, client->media_rcv_buf->data, len);
        enum ice_payload_type type = ice_get_payload_type(client->media_rcv_buf->data, len);
        if (type == ICE_PAYLOAD_STUN)
            /*LLOG(LL_TRACE, "got stun msg size %d", len)*/;
        else if (type == ICE_PAYLOAD_DTLS)
            dtls_handler(client, client->media_rcv_buf->data, len);
        else if (type == ICE_PAYLOAD_RTP)
            /*LLOG(LL_TRACE, "got rtp size %d", len)*/;
        else if (type == ICE_PAYLOAD_RTCP)
            /*LLOG(LL_TRACE, "got rtcp size %d", len)*/;
        rtz_update_stats(client, 2 + len, 0);
    }
}

void rtz_media_event_handler(tcp_chan_t *chan, int status, void *udata)
{
    rtz_client_t *client = udata;
    if (status > 0) {
        LLOG(LL_TRACE, "client %p media channel connected", udata);
        client->media_chan_writer = tcp_simple_writer_new(chan);
        client->flag |= RTZ_CLIENT_MEDIA_CONNECTED;
        rtz_client_srtp_create(client);
        client->stun_timer = zl_timer_start(client->loop, 1000, 1000,
                                            rtz_client_stun_timeout_handler, client);
        rtz_client_stun_timeout_handler(client->loop, client->stun_timer, client);

        SSL_set_connect_state(client->ssl);
        int ret;
        char data[1500];
        ret = SSL_do_handshake(client->ssl);
        ret = SSL_get_error(client->ssl, ret);
        ret = BIO_read(client->write_bio, data, sizeof(data));
        if (ret > 0)
            send_media_data(client, data, ret);
    } else {
        LLOG(LL_ERROR, "%p media channel event %d", udata, status);
        client->flag = RTZ_CLIENT_ERROR;
    }
}

void send_media_data(rtz_client_t *client, const void *data, int size)
{
    if (!client->media_chan)
        return;
    if (!(client->flag & RTZ_CLIENT_MEDIA_CONNECTED))
        return;
    assert(size < 65536);
    uint8_t hdr[2];
    hdr[0] = (size & 0xff00) >> 8;
    hdr[1] = size & 0xff;
    struct iovec iov[2] = {
        { hdr, 2 },
        { (void*)data, size },
    };
    tcp_simple_writer_performv(client->media_chan_writer, iov, 2);
    rtz_update_stats(client, 0, 2 + size);
}

void rtz_client_stun_timeout_handler(zl_loop_t *loop, int timer, void *udata)
{
    rtz_client_t *client = udata;
    char msg_buf[1024];
    char stun_user[32];
    stun_msg_hdr_t *msg_hdr = (stun_msg_hdr_t*)msg_buf;

    // STUN Request
    snprintf(stun_user, sizeof(stun_user), "%s:%s", client->ice_ruser->data,
             client->ice_luser->data);
    stun_msg_hdr_init(msg_hdr, STUN_BINDING_REQUEST, msg_hdr->tsx_id);
    //stun_attr_xor_sockaddr_add(msg_hdr, STUN_ATTR_XOR_MAPPED_ADDRESS, addr);
    stun_attr_varsize_add(msg_hdr, STUN_ATTR_USERNAME,
                          stun_user, strlen(stun_user), ' ');
    stun_attr_varsize_add(msg_hdr, STUN_ATTR_PASSWORD,
                          client->ice_rpwd->data, client->ice_rpwd->size, ' ');
    stun_attr_msgint_add(msg_hdr, client->ice_lpwd->data, client->ice_lpwd->size);
    stun_attr_fingerprint_add(msg_hdr);
    send_media_data(client, msg_hdr, stun_msg_len(msg_hdr));
}

void rtz_client_rtcp_timeout_handler(zl_loop_t *loop, int timer, void *udata)
{
    rtz_client_t *client = udata;
    if (!client->srtp_valid)
        return;

    char rtcpbuf[1024];
    rtcp_rr *rr = (rtcp_rr*)&rtcpbuf;
    int rrlen = sizeof(rtcp_rr);
    rr->header.version = 2;
    rr->header.type = RTCP_RR;
    rr->header.rc = 1;
    rr->header.length = htons((rrlen / 4) - 1);
    rr->ssrc = htonl(client->video_ssrc);
    memset(&rr->rb[0], 0, sizeof(report_block));
    rr->rb[0].ssrc = rr->ssrc;
    int remblen = rtcp_remb(rtcpbuf + rrlen, 64, 8388608); // 8Mbps
    int plen = rrlen + remblen;
    int ret = srtp_protect_rtcp(client->srtp_out, rtcpbuf, &plen);
    if (ret == srtp_err_status_ok)
        send_media_data(client, rtcpbuf, plen);
}

void dtls_handler(rtz_client_t *client, const void *buf, int len)
{
    //LLOG(LL_DEBUG, "dtls handler len=%d", len);
    int written = BIO_write(client->read_bio, buf, len);
    if (written != len) {
        LLOG(LL_WARN, "Only written %d/%d of those bytes on the read BIO...", written, len);
    } else {
        //LLOG(LL_TRACE, "Written %d bytes on the read BIO...", written);
    }
    /* Try to read data */
    char data[1500];	/* FIXME */
    memset(&data, 0, 1500);
    int read = SSL_read(client->ssl, &data, 1500);
    //LLOG(LL_TRACE, "   ... and read %d of them from SSL...", read);
    if (read < 0) {
        unsigned long err = SSL_get_error(client->ssl, read);
        if (err == SSL_ERROR_SSL) {
            /* Ops, something went wrong with the DTLS handshake */
            char error[200];
            ERR_error_string_n(ERR_get_error(), error, 200);
            LLOG(LL_ERROR, "Handshake error: %s", error);
            return;
        } else if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            read = BIO_read(client->write_bio, data, sizeof(data));
            if (read > 0)
                send_media_data(client, data, read);
        }
    }
    if (!SSL_is_init_finished(client->ssl)) {
        //LLOG(LL_TRACE, "Initialization not finished yet...");
        /* Nothing else to do for now */
        return;
    }
    //LLOG(LL_TRACE, "DTLS established, yay!");
    /* Check the remote fingerprint */
    X509 *rcert = SSL_get_peer_certificate(client->ssl);
    if (!rcert) {
        LLOG(LL_ERROR, "No remote certificate?? (%s)",
             ERR_reason_error_string(ERR_get_error()));
    } else {
        unsigned int rsize;
        unsigned char rfingerprint[EVP_MAX_MD_SIZE];
        char remote_fingerprint[160];
        char *rfp = (char *)&remote_fingerprint;
        sbuf_t *remote_hashing = client->rhash;
        sbuf_t *jsep_remote_fingerprint = client->rfingerprint;
        const char *digest_method;
        if (!strcasecmp(remote_hashing->data, "sha-1")) {
            //LLOG(LL_TRACE, "Computing sha-1 fingerprint of remote certificate...");
            digest_method = "sha-1";
            X509_digest(rcert, EVP_sha1(), rfingerprint, &rsize);
        } else {
            //LLOG(LL_TRACE, "Computing sha-256 fingerprint of remote certificate...");
            digest_method = "sha-256";
            X509_digest(rcert, EVP_sha256(), rfingerprint, &rsize);
        }
        X509_free(rcert);
        rcert = NULL;
        unsigned int i = 0;
        for (i = 0; i < rsize; i++) {
            snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
            rfp += 3;
        }
        *(rfp - 1) = 0;
        //LLOG(LL_TRACE, "Remote fingerprint (%s) of the client is %s",
        //     digest_method, remote_fingerprint);
        if (sbuf_empty(jsep_remote_fingerprint) || !strcasecmp("(none)", jsep_remote_fingerprint->data)
            || !strcasecmp(remote_fingerprint, jsep_remote_fingerprint->data)) {

            //LLOG(LL_TRACE, "Fingerprint is a match!");
            client->dtls_state = DTLS_STATE_CONNECTED;
        } else {
            /* FIXME NOT a match! MITM? */
            LLOG(LL_ERROR, "Fingerprint is NOT a match! got %s, expected %s", remote_fingerprint, jsep_remote_fingerprint->data);
            client->dtls_state = DTLS_STATE_FAILED;
            goto done;
        }
        if (client->dtls_state == DTLS_STATE_CONNECTED) {
            /* Which SRTP profile is being negotiated? */
            SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(client->ssl);
            if (srtp_profile == NULL) {
                /* Should never happen, but just in case... */
                LLOG(LL_ERROR, "No SRTP profile selected...");
                client->dtls_state = DTLS_STATE_FAILED;
                goto done;
            }
            //LLOG(LL_TRACE, "SRTP Profile %s", srtp_profile->name);
            int key_length = 0, salt_length = 0, master_length = 0;
            switch (srtp_profile->id) {
            case SRTP_AES128_CM_SHA1_80:
            case SRTP_AES128_CM_SHA1_32:
                key_length = SRTP_MASTER_KEY_LENGTH;
                salt_length = SRTP_MASTER_SALT_LENGTH;
                master_length = SRTP_MASTER_LENGTH;
                break;
            case SRTP_AEAD_AES_256_GCM:
                key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
                salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
                master_length = SRTP_AESGCM256_MASTER_LENGTH;
                break;
            case SRTP_AEAD_AES_128_GCM:
                key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
                salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
                master_length = SRTP_AESGCM128_MASTER_LENGTH;
                break;
            default:
                /* Will never happen? */
                LLOG(LL_WARN, "Unsupported SRTP profile %lu", srtp_profile->id);
                break;
            }
            //LLOG(LL_TRACE, "Key/Salt/Master: %d/%d/%d", master_length, key_length, salt_length);
            /* Complete with SRTP setup */
            unsigned char material[master_length * 2];
            unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
            /* Export keying material for SRTP */
            if (!SSL_export_keying_material(client->ssl, material, master_length * 2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
                /* Oops... */
                LLOG(LL_ERROR, "Oops, couldn't extract SRTP keying material for component in stream?? (%s)",
                     ERR_reason_error_string(ERR_get_error()));
                goto done;
            }
            /* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
            // client->dtls_role == DTLS_ROLE_CLIENT
            local_key = material;
            remote_key = local_key + key_length;
            local_salt = remote_key + key_length;
            remote_salt = local_salt + salt_length;
            /* Build master keys and set SRTP policies */
            /* Remote (inbound) */
            switch (srtp_profile->id) {
            case SRTP_AES128_CM_SHA1_80:
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->remote_policy.rtp));
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->remote_policy.rtcp));
                break;
            case SRTP_AES128_CM_SHA1_32:
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(client->remote_policy.rtp));
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->remote_policy.rtcp));
                break;
            case SRTP_AEAD_AES_256_GCM:
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(client->remote_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(client->remote_policy.rtcp));
                break;
            case SRTP_AEAD_AES_128_GCM:
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(client->remote_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(client->remote_policy.rtcp));
                break;
            default:
                /* Will never happen? */
                LLOG(LL_WARN, "Unsupported SRTP profile %s", srtp_profile->name);
                break;
            }
            client->remote_policy.ssrc.type = ssrc_any_inbound;
            unsigned char remote_policy_key[master_length];
            client->remote_policy.key = (unsigned char *)&remote_policy_key;
            memcpy(client->remote_policy.key, remote_key, key_length);
            memcpy(client->remote_policy.key + key_length, remote_salt, salt_length);
            client->remote_policy.window_size = 128;
            client->remote_policy.allow_repeat_tx = 0;
            client->remote_policy.next = NULL;
            /* Local (outbound) */
            switch (srtp_profile->id) {
            case SRTP_AES128_CM_SHA1_80:
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->local_policy.rtp));
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->local_policy.rtcp));
                break;
            case SRTP_AES128_CM_SHA1_32:
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(client->local_policy.rtp));
                srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(client->local_policy.rtcp));
                break;
            case SRTP_AEAD_AES_256_GCM:
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(client->local_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_256_16_auth(&(client->local_policy.rtcp));
                break;
            case SRTP_AEAD_AES_128_GCM:
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(client->local_policy.rtp));
                srtp_crypto_policy_set_aes_gcm_128_16_auth(&(client->local_policy.rtcp));
                break;
            default:
                /* Will never happen? */
                LLOG(LL_WARN, "Unsupported SRTP profile %s", srtp_profile->name);
                break;
            }
            client->local_policy.ssrc.type = ssrc_any_outbound;
            unsigned char local_policy_key[master_length];
            client->local_policy.key = (unsigned char *)&local_policy_key;
            memcpy(client->local_policy.key, local_key, key_length);
            memcpy(client->local_policy.key + key_length, local_salt, salt_length);
            client->local_policy.window_size = 128;
            client->local_policy.allow_repeat_tx = 0;
            client->local_policy.next = NULL;
            /* Create SRTP sessions */
            srtp_err_status_t res = srtp_create(&(client->srtp_in), &(client->remote_policy));
            if (res != srtp_err_status_ok) {
                /* Something went wrong... */
                LLOG(LL_ERROR, "Oops, error creating inbound SRTP session for component in stream??");
                LLOG(LL_ERROR, "  -- %d (%s)\n", res, rtz_srtp_error_str(res));
                goto done;
            }
            //LLOG(LL_TRACE, "Created inbound SRTP session for component in stream");
            res = srtp_create(&(client->srtp_out), &(client->local_policy));
            if (res != srtp_err_status_ok) {
                /* Something went wrong... */
                LLOG(LL_ERROR, "Oops, error creating outbound SRTP session for component in stream??");
                LLOG(LL_ERROR, "  -- %d (%s)", res, rtz_srtp_error_str(res));
                goto done;
            }
            client->srtp_profile = srtp_profile->id;
            client->srtp_valid = 1;
            //LLOG(LL_TRACE, "Created outbound SRTP session for component in stream");
        }
done:
        if (client->srtp_valid) {
            /* Handshake successfully completed */
            LLOG(LL_DEBUG, "client %p dtls handshake done", client);
            client->rtcp_timer = zl_timer_start(client->loop, 200, 200,
                                                rtz_client_rtcp_timeout_handler, client);
        } else {
            /* Something went wrong in either DTLS or SRTP... */
            //dtls_callback(client->ssl, SSL_CB_ALERT, 0);
            LLOG(LL_ERROR, "client %p dtls alert", client);
        }
    }
}

void rtz_client_srtp_create(rtz_client_t *client)
{
    /* Create SSL context, at last */
    client->srtp_valid = 0;
    client->ssl = SSL_new(dtls_srtp_get_ssl_ctx());
    if (!client->ssl) {
        LLOG(LL_ERROR, "Error creating DTLS session! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        return;
    }
    SSL_set_ex_data(client->ssl, 0, client);
    //SSL_set_info_callback(client->ssl, dtls_callback);
    client->read_bio = BIO_new(BIO_s_mem());
    if (!client->read_bio) {
        LLOG(LL_ERROR, "Error creating read BIO! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        SSL_free(client->ssl);
        return;
    }
    BIO_set_mem_eof_return(client->read_bio, -1);
    client->write_bio = BIO_new(BIO_s_mem());
    if (!client->write_bio) {
        LLOG(LL_ERROR, "Error creating write BIO! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        BIO_free(client->read_bio);
        SSL_free(client->ssl);
        return;
    }
    SSL_set_bio(client->ssl, client->read_bio, client->write_bio);
    /* The role may change later, depending on the negotiation */
    /* https://code.google.com/p/chromium/issues/detail?id=406458
     * Specify an ECDH group for ECDHE ciphers, otherwise they cannot be
     * negotiated when acting as the server. Use NIST's P-256 which is
     * commonly supported.
     */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh == NULL) {
        LLOG(LL_ERROR, "Error creating ECDH group! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        SSL_free(client->ssl);
        client->ssl = NULL;
        return;
    }
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_ECDH_USE;
    SSL_set_options(client->ssl, flags);
    SSL_set_tmp_ecdh(client->ssl, ecdh);
    EC_KEY_free(ecdh);
}

void rtz_update_stats(void *rtz_handle, int recv_bytes, int send_bytes)
{
    rtz_client_t *client = rtz_handle;
    client->recv_bytes += recv_bytes;
    client->send_bytes += send_bytes;
}
