#include "rtmp_client.h"
#include "event_loop.h"
#include "sbuf.h"
#include "net_util.h"
#include "log.h"
#include "algo/base64.h"
#include "algo/md5.h"
#include "list.h"
#include "pack_util.h"
#include "rtmp_types.h"
#include "media/codec_types.h"
#include "media/rtp_types.h"
#include "media/h26x.h"
#include "tcp_chan.h"
#include "timestamp.h"
#include "rtz_server.h"
#include "rtmp_server.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <math.h>

enum {
    RTMP_CLIENT_URI_SIZE = 4096,
    RTMP_CLIENT_IP_SIZE = 64,
    RTMP_CLIENT_RCV_BUF_SIZE = 65536,
    RTMP_CLIENT_SND_BUF_SIZE = 65536,
    RTMP_CLIENT_DEFAULT_PORT = 1935,
    RTMP_CLIENT_TIMEOUT_MSECS = 3000,
};

enum rtmp_client_flag {
    RTMP_CLIENT_IN_EVENT_CB = 1,
    RTMP_CLIENT_ERROR = 2,
    RTMP_CLIENT_EOF = 4,
};

typedef enum rtmp_parse_state_t {
    RTMP_PARSE_INIT,
    RTMP_PARSE_CHUNK_HEADER,
    RTMP_PARSE_CHUNK_BODY,
    NUM_RTMP_PARSE_STATES,
} rtmp_parse_state_t;

typedef enum rtmp_handshake_state_t {
    RTMP_HS_INIT,
    RTMP_HS_WAIT_S1,
    RTMP_HS_WAIT_S2,
    RTMP_HS_DONE,
} rtmp_handshake_state_t;

struct rtmp_client_t {
    zl_loop_t *loop;
    tcp_chan_t *chan;
    sbuf_t *chunk_body[RTMP_MAX_CHUNK_STREAMS];

    sbuf_t *uri;
    sbuf_t *ip;
    unsigned short port;
    sbuf_t *app;
    sbuf_t *stream;
    rtz_stream_t *rtz_stream;

    rtmp_handshake_state_t hstate;
    rtmp_parse_state_t pstate;
    rtmp_chunk_t last_chunks[RTMP_MAX_CHUNK_STREAMS];
    unsigned next_tx_id;
    rtmp_chunk_t cur_chunk;
    int recv_body_size_limit;
    char header[RTMP_MAX_CHUNK_HEADER_SIZE];
    unsigned char expected_hlen;

    tsc_t *video_tsc;
    tsc_t *audio_tsc;
    int64_t last_audio_timestamp;
    uint64_t video_counter;
    uint64_t audio_counter;

    video_codec_t *vcodec;
    audio_codec_t *acodec;

    double duration;
    float sframe_time;
    int64_t last_video_ts;

    void *udata;
    long long connect_timestamp;

    //int vcodec_changed;

    int flag;
    struct list_head link;
    struct list_head request_list;

    long long last_time;
};

typedef struct rtmp_request_t {
    rtmp_client_t *client;
    long long timestamp;
    const char *method;
    unsigned char channel;
    unsigned tx_id;
    sbuf_t *buf;
    //rtsp_request_cb cb;
    zl_defer_cb ucb;
    struct list_head link;
} rtmp_request_t;

static rtmp_request_t *rtmp_request_new(rtmp_client_t *client, const char *method,
                                        unsigned channel, zl_defer_cb ucb);
static void rtmp_request_del(rtmp_request_t *req);
static void send_c01(rtmp_client_t *client);
static void send_c2(rtmp_client_t *client, const char *s1);
static void handshake_handler(rtmp_client_t *client);
static void session_handler(rtmp_client_t *client);
static void audio_handler(rtmp_client_t *peer, int64_t timestamp,
                          const char *data, int size);
static void video_nalu_handler(rtmp_client_t *peer, int64_t timestamp,
                               const char *data, int size);
static void video_avc_handler(rtmp_client_t *peer, int64_t timestamp,
                              const char *data, int size);
static void notify_handler(rtmp_client_t *peer, const char *cmd,
                           const char *data, int size);
static void event_handler(rtmp_client_t *peer, rtmp_event_type_t type,
                          const char *data, int size);
static void command_handler(rtmp_client_t *peer, unsigned channel, const char *cmd,
                            unsigned tx_id, const char *data, int size);
static void metadata_handler(rtmp_client_t *peer, const char *data, int size);
static void recv_handler(rtmp_client_t *client, const char *data, int size);
static void chunk_handler(rtmp_client_t *client);
static void send_connect(rtmp_client_t *client, zl_defer_cb ucb);
static void send_create_stream(rtmp_client_t *client, zl_defer_cb ucb);
static void send_release_stream(rtmp_client_t *client, zl_defer_cb ucb);
static void send_fcpublish(rtmp_client_t *client, zl_defer_cb ucb);
static void send_publish(rtmp_client_t *client, zl_defer_cb ucb);
static void send_play(rtmp_client_t *client, zl_defer_cb ucb);
static void send_video(rtmp_client_t *client, uint32_t timestamp, const void *data, int size);
static int is_publish_status(int64_t status);
static void finish_requests(rtmp_client_t *client, unsigned tx_id, int64_t status);
static rtmp_status_t convert_to_status(const char *data, size_t size);
static const char *get_status_text(rtmp_status_t status);
static void rtmp_client_data_handler(tcp_chan_t *chan, void *udata);
static void rtmp_client_event_handler(tcp_chan_t *chan, int status, void *udata);
static void rtmp_write_handler(const void *data, int size, void *udata);

rtmp_client_t *rtmp_client_new(zl_loop_t *loop)
{
    rtmp_client_t *client = malloc(sizeof(rtmp_client_t));
    memset(client, 0, sizeof(rtmp_client_t));
    client->loop = loop;
    client->udata = client;
    client->uri = sbuf_new1(RTMP_CLIENT_URI_SIZE);
    client->ip = sbuf_new1(RTMP_CLIENT_IP_SIZE);
    client->app = sbuf_new();
    client->stream = sbuf_new();
    client->chan = NULL;
    client->hstate = RTMP_HS_INIT;
    client->pstate = RTMP_PARSE_INIT;
    client->recv_body_size_limit = RTMP_DEFAULT_CHUNK_BODY_SIZE;
    client->next_tx_id = 1;
    client->video_tsc = tsc_new(32, 4000, 40);
    client->audio_tsc = tsc_new(32, 4000, 40);
    client->vcodec = video_codec_new();
    client->acodec = audio_codec_new();
    //client->vcodec_changed = 1;

    INIT_LIST_HEAD(&client->request_list);
    return client;
}
/*
void rtmp_client_set_userdata(rtmp_client_t *client, void *udata)
{
    client->udata = udata;
}
*/
void rtmp_client_del(rtmp_client_t *client)
{
    if (client->chan) {
        tcp_chan_close(client->chan, 0);
        client->chan = NULL;
    }
    
    rtmp_request_t *req, *tmp;
    list_for_each_entry_safe(req, tmp, &client->request_list, link) {
        rtmp_request_del(req);
    }
    INIT_LIST_HEAD(&client->request_list);

    int i;
    for (i = 0; i < RTMP_MAX_CHUNK_STREAMS; ++i)
        if (client->chunk_body[i])
            sbuf_del(client->chunk_body[i]);
    sbuf_del(client->uri);
    sbuf_del(client->ip);
    sbuf_del(client->app);
    sbuf_del(client->stream);
    tsc_del(client->video_tsc);
    tsc_del(client->audio_tsc);
    video_codec_del(client->vcodec);
    audio_codec_del(client->acodec);
    free(client);
}

void rtmp_client_set_uri(rtmp_client_t *client, const char *uri)
{
    sbuf_strcpy(client->uri, uri);
    char *ip = NULL;
    int n;
    n = sscanf(client->uri->data, "rtmp://%m[0-9.]:%hu", &ip, &client->port);
    if (n >= 1)
        sbuf_strcpy(client->ip, ip);
    if (n < 2)
        client->port = RTMP_CLIENT_DEFAULT_PORT;
    free(ip);
    char *p = strchr(client->uri->data + 7, '/');
    if (p) {
        char *q = strchr(p + 1, '/');
        if (q) {
            sbuf_strncpy(client->app, p + 1, q - (p + 1));
            sbuf_strcpy(client->stream, q + 1);
        } else {
            sbuf_strcpy(client->app, p + 1);
        }
    }
    LLOG(LL_TRACE, "ip=%s port=%hu app=%s stream=%s", client->ip->data,
         client->port, client->app->data, client->stream->data);
}

void rtmp_client_tcp_connect(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    client->chan = tcp_connect(client->loop, client->ip->data, client->port);
    tcp_chan_set_cb(client->chan, rtmp_client_data_handler, NULL, rtmp_client_event_handler, client);
}

void rtmp_client_data_handler(tcp_chan_t *chan, void *udata)
{
    rtmp_client_t *client = udata;
    client->flag |= RTMP_CLIENT_IN_EVENT_CB;
    if (client->hstate != RTMP_HS_DONE)
        handshake_handler(client);
    if (client->hstate == RTMP_HS_DONE)
        session_handler(client);
    client->flag &= ~RTMP_CLIENT_IN_EVENT_CB;
    if (client->flag & (RTMP_CLIENT_ERROR | RTMP_CLIENT_EOF)) {
        LLOG(LL_ERROR, "rtmp_client %p error, flag %d", client, client->flag);
        rtmp_client_abort(client);
    }
}

void rtmp_client_event_handler(tcp_chan_t *chan, int status, void *udata)
{
    LLOG(LL_TRACE, "rtmp_client %p event %d", udata, status);
    rtmp_client_t *client = udata;
    if (status > 0) {
        /* Connected */
        send_c01(client);
        client->hstate = RTMP_HS_WAIT_S1;
    } else {
        /* EOF or socket error */
        rtmp_client_abort(client);
    }
}

void rtmp_client_connect(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_connect(client, func);
}

void rtmp_client_create_stream(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_create_stream(client, func);
}

void rtmp_client_play(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_play(client, func);
}

void rtmp_client_release_stream(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_release_stream(client, func);
}

void rtmp_client_fcpublish(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_fcpublish(client, func);
}

void rtmp_client_publish(rtmp_client_t *client, zl_defer_cb func)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        zl_defer(client->loop, func, -EINVAL, client->udata);
        return;
    }

    send_publish(client, func);
}

void rtmp_client_abort(rtmp_client_t *client)
{
    if (client->chan) {
        tcp_chan_close(client->chan, 0);
        client->chan = NULL;
    }
    /*
    error_handler(client, -ECANCELED);
    if (client->fd != -1) {
        zl_fd_ctl(client->loop, EPOLL_CTL_DEL, client->fd, 0, NULL, NULL);
        close(client->fd);
        client->fd = -1;
    }
    */
}

void rtmp_client_set_rtz_stream(rtmp_client_t *client, void *rtz_stream)
{
    client->rtz_stream = rtz_stream;
}

/*
void rtmp_client_set_video_packet_cb(rtmp_client_t *client, rtmp_packet_cb func)
{
    client->video_cb = func;
}

void rtmp_client_set_audio_packet_cb(rtmp_client_t *client, rtmp_packet_cb func)
{
    client->audio_cb = func;
}

void rtmp_client_send_video(rtmp_client_t *client, uint32_t timestamp, const char *data, int size)
{
    if (client->flag & RTMP_CLIENT_ERROR) {
        return;
    }

    send_video(client, timestamp, data, size);
}
*/
void send_c01(rtmp_client_t *client)
{
    char data[RTMP_HANDSHAKE_C0_SIZE + RTMP_HANDSHAKE_C1_SIZE];
    char *p = data;

    *p++ = RTMP_HANDSHAKE_C0; /* Version */
    uint32_t now = (uint32_t)(zl_time() / 1000);
    p += pack_be32(p, now);
    p += pack_be32(p, 0);
    memset(p, 0, RTMP_HANDSHAKE_C1_SIZE - 8);
    tcp_chan_write(client->chan, data, sizeof(data));
}

void session_handler(rtmp_client_t *client)
{
    //LLOG(LL_TRACE, "read_buf size=%d", tcp_chan_get_read_buf_size(peer->chan));
    while (!tcp_chan_read_buf_empty(client->chan)) {
        if (client->pstate == RTMP_PARSE_INIT) {
            client->pstate = RTMP_PARSE_CHUNK_HEADER;
        } else if (client->pstate == RTMP_PARSE_CHUNK_HEADER) {
            unsigned char fmt = rtmp_chunk_header_fmt(tcp_chan_peekc(client->chan));
            int hdr_len = rtmp_chunk_header_len(fmt);
            int buf_len = tcp_chan_get_read_buf_size(client->chan);
            if (fmt == 0 || fmt == 1 || fmt == 2) {
                if (buf_len < 4)
                    break;
                uint8_t tmp_buf[4];
                tcp_chan_peek(client->chan, tmp_buf, 4);
                if (unpack_be24(tmp_buf + 1) == 0xffffff) {
                    client->cur_chunk.ext_timestamp_present = 1;
                    hdr_len += 4;
                } else {
                    client->cur_chunk.ext_timestamp_present = 0;
                }
            } else if (fmt == 3) {
                if (client->cur_chunk.ext_timestamp_present)
                    hdr_len += 4;
            }
            if (buf_len < hdr_len)
                break;

            tcp_chan_read(client->chan, client->header, hdr_len);
            client->cur_chunk.chunk_channel = rtmp_chunk_channel(client->header[0]);
            if (fmt == 0) {
                if (client->cur_chunk.ext_timestamp_present) {
                    client->cur_chunk.timestamp = unpack_be32(client->header + RTMP_CHUNK_HEADER_SIZE_FMT0);
                } else {
                    client->cur_chunk.timestamp = unpack_be24(&client->header[1]);
                }
                client->cur_chunk.body_size = unpack_be24(&client->header[4]);
                client->cur_chunk.type_id = (unsigned char)client->header[7];
                client->cur_chunk.msg_stream_id = unpack_le32 (&client->header[8]);
                memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                       &client->cur_chunk, sizeof(rtmp_chunk_t));
            } else if (fmt == 1) {
                if (client->cur_chunk.ext_timestamp_present) {
                    client->cur_chunk.timestamp_delta = unpack_be32(client->header + RTMP_CHUNK_HEADER_SIZE_FMT1);
                } else {
                    client->cur_chunk.timestamp_delta = unpack_be24(&client->header[1]);
                }
                client->cur_chunk.body_size = unpack_be24(&client->header[4]);
                client->cur_chunk.type_id = (unsigned char)client->header[7];
                client->cur_chunk.timestamp = client->last_chunks[client->cur_chunk.chunk_channel].timestamp
                    + client->cur_chunk.timestamp_delta;
                memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                       &client->cur_chunk, sizeof(rtmp_chunk_t));
            } else if (fmt == 2) {
                rtmp_chunk_t *lc = &client->last_chunks[client->cur_chunk.chunk_channel];
                if (client->cur_chunk.ext_timestamp_present) {
                    client->cur_chunk.timestamp_delta = unpack_be32(client->header + RTMP_CHUNK_HEADER_SIZE_FMT2);
                } else {
                    client->cur_chunk.timestamp_delta = unpack_be24(&client->header[1]);
                }
                client->cur_chunk.body_size = lc->body_size;
                client->cur_chunk.type_id = lc->type_id;
                client->cur_chunk.timestamp = lc->timestamp + client->cur_chunk.timestamp_delta;
                memcpy(&client->last_chunks[client->cur_chunk.chunk_channel],
                       &client->cur_chunk, sizeof(rtmp_chunk_t));
            } else {
                rtmp_chunk_t *lc = &client->last_chunks[client->cur_chunk.chunk_channel];
                client->cur_chunk.body_size = lc->body_size;
                client->cur_chunk.type_id = lc->type_id;
                client->cur_chunk.timestamp = lc->timestamp;
            }
            //LLOG(LL_TRACE, "fmt=%d chan=%d cur_chunk.body_size=%d",
            //    (int)fmt, (int)peer->cur_chunk.chunk_channel, peer->cur_chunk.body_size);
            //LLOG(LL_TRACE, "header chan=%hhu fmt=%hhu timestamp=%u hdr_len=%d body_size=%d",
            //     peer->cur_chunk.chunk_channel, fmt, peer->cur_chunk.timestamp, hdr_len,
            //     peer->cur_chunk.body_size);
            client->pstate = RTMP_PARSE_CHUNK_BODY;
        } else if (client->pstate == RTMP_PARSE_CHUNK_BODY) {
            sbuf_t *chunk_body = client->chunk_body[client->cur_chunk.chunk_channel];
            if (!chunk_body)
                chunk_body = client->chunk_body[client->cur_chunk.chunk_channel] = sbuf_new();
            int n = client->cur_chunk.body_size - chunk_body->size;
            if (n < 0) {
                LLOG(LL_ERROR, "%s parse error, body_size=%d chunk_size=%d.",
                     client->stream->data, client->cur_chunk.body_size, chunk_body->size);
                client->flag |= RTMP_CLIENT_ERROR;
                break;
            }
            if (n > tcp_chan_get_read_buf_size(client->chan))
                n = tcp_chan_get_read_buf_size(client->chan);
            int m = client->recv_body_size_limit - (chunk_body->size % client->recv_body_size_limit);
            if (n > m)
                n = m;
            int old_size = chunk_body->size;
            sbuf_resize(chunk_body, old_size + n);
            tcp_chan_read(client->chan, chunk_body->data + old_size, n);
            //LLOG(LL_TRACE, "%d %d %d", peer->cur_chunk.body_size, chunk_body->size, peer->last_chunks[peer->cur_chunk.chunk_channel].body_size);
            if (chunk_body->size % client->recv_body_size_limit == 0) {
                //LLOG(LL_TRACE, "  chunk size %d limit reached, total %d", peer->chunk_body->size, peer->cur_chunk.body_size);
                client->pstate = RTMP_PARSE_INIT;
            }
            if (chunk_body->size == client->cur_chunk.body_size) {
                //log_info ("buffer_size={} hdr_size={} body_size={}", _buffer.size (), _chunk_header.header_size, _chunk_header.body_size);
                chunk_handler(client);
                sbuf_clear(chunk_body);
                client->pstate = RTMP_PARSE_INIT;
            }
        }
    }
}

void send_c2(rtmp_client_t *client, const char *s1)
{
    tcp_chan_write(client->chan, s1, RTMP_HANDSHAKE_C2_SIZE);
}
#if 0
void error_handler(rtmp_client_t *client, int err)
{
    if (client->connect_cb) {
        zl_defer_cb cb = client->connect_cb;
        client->connect_cb = NULL;
        cb(client->loop, err, client->udata);
    }
    /*
    rtsp_request_t *req;
    while (!list_empty(&client->request_list)) {
        req = list_entry(client->request_list.next, rtsp_request_t, link);
        list_del_init(&req->link);
        if (req->ucb)
            req->ucb(client->loop, err, client->udata);
        rtsp_request_del(req);
    }
    */
}
#endif
void chunk_handler(rtmp_client_t *client)
{
    rtmp_chunk_t *hdr = &client->cur_chunk;
    char *data = client->chunk_body[hdr->chunk_channel]->data;
    int size = client->chunk_body[hdr->chunk_channel]->size;
    sbuf_t *cmd_name = sbuf_new();
    if (hdr->type_id == RTMP_MESSAGE_SET_CHUNK_SIZE) {
        if (hdr->body_size == 4) {
            uint32_t chunk_size = unpack_be32(data) & 0x7fffffff;
            //LLOG(LL_TRACE, "SetChunkSize %d", (int)chunk_size);
            client->recv_body_size_limit = chunk_size;
        } else {
            LLOG(LL_ERROR, "invalid SetChunkSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_ABORT) {
        LLOG(LL_TRACE, "Abort Message");
    } else if (hdr->type_id == RTMP_MESSAGE_ACK) {
        if (hdr->body_size == 4) {
            uint32_t seq = unpack_be32(data);
            //LLOG(LL_TRACE, "Ack seq=%d", (int)seq);
        } else {
            LLOG(LL_ERROR, "invalid Ack body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_USER_CONTROL) {
        if (hdr->body_size >= 2) {
            rtmp_event_type_t etype = unpack_be16(data);
            char *edata = data + 2;
            uint32_t esize = hdr->body_size - 2;
            event_handler(client, etype, edata, esize);
            //LLOG(LL_TRACE, "UserControl event_type=%d event_size=%d", (int)etype, (int)esize);
        } else {
            LLOG(LL_ERROR, "UserControl invalid body_size=%d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_WINDOW_ACK_SIZE) {
        if (hdr->body_size == 4) {
            uint32_t size = unpack_be32(data);
            LLOG(LL_TRACE, "window ack size=%d", (int)size);
            //_wnd_ack_size = size;
            //SendWindowAckSize ();
        } else {
            LLOG(LL_ERROR, "invalid WindowAckSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_SET_PEER_BANDWIDTH) {
        if (hdr->body_size == 5) {
            uint32_t size = unpack_be32(data);
            unsigned char limit_type = (unsigned char)data[4];
            LLOG(LL_TRACE, "SetPeerBandwidth size=%d limit_type=%hhu", (int)size, limit_type);
        } else {
            LLOG(LL_ERROR, "invalid WindowAckSize body size %d", (int)hdr->body_size);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AUDIO) {
        int64_t timestamp = tsc_timestamp(client->audio_tsc, hdr->timestamp);
        audio_handler(client, timestamp, data, size);
    } else if (hdr->type_id == RTMP_MESSAGE_VIDEO) {
        //LLOG(LL_TRACE, "video size=%d data=%02hhx%02hhx%02hhx%02hhx", (int)size, data[0], data[1], data[2], data[3]);
        int64_t timestamp = tsc_timestamp(client->video_tsc, hdr->timestamp);

        /* Update frame_time */
        int64_t frame_time = timestamp - client->last_video_ts;
        float old_sframe_time = client->sframe_time;
        if (0 < frame_time && frame_time < 1000) {
            if (client->sframe_time)
                client->sframe_time = (frame_time + 3 * client->sframe_time) / 4.0f;
            else
                client->sframe_time = frame_time;
        }
        //LLOG(LL_TRACE, "frame_time=%ld old_sframe_time=%.0f sframe_time=%.0f",
        //     frame_time, old_sframe_time, client->sframe_time);
        client->last_video_ts = timestamp;

        if (size > 5) {
            if ((data[0] & 0xf) == 7) { // AVC Codec
                char *p = data + 5;
                int psize = size - 5;
                if (data[1] == 0) {
                    video_avc_handler(client, timestamp, p, psize);
                } else {
                    int frame_cnt = 0;
                    while (psize > 4) {
                        uint32_t nalu_size = unpack_be32(p);
                        if (4 + nalu_size <= psize && nalu_size > 0) {
                            unsigned nalu_type = p[4] & 0x1f;
                            if (nalu_type == 5 || nalu_type == 1) {
                                if (nalu_type == 5) {
                                    //LLOG(LL_TRACE, "%s: orig_ts=%u ts=%ld", peer->app->data, hdr->timestamp, timestamp);
                                }
                                ++frame_cnt;
                                video_nalu_handler(client, timestamp, p + 4, nalu_size);
                            } else {
                                if (nalu_type == 7) {
                                    sbuf_strncpy(client->vcodec->sps_data, p + 4, nalu_size);
                                } else if (nalu_type == 8) {
                                    sbuf_strncpy(client->vcodec->pps_data, p + 4, nalu_size);
                                    if (!sbuf_empty(client->vcodec->sps_data) && !sbuf_empty(client->vcodec->pps_data)) {
                                        sbuf_t *avc = make_h264_decoder_config_record(client->vcodec->sps_data->data, client->vcodec->sps_data->size,
                                                                                      client->vcodec->pps_data->data, client->vcodec->pps_data->size);
                                        video_avc_handler(client, timestamp, avc->data, avc->size);
                                        sbuf_del(avc);
                                    }
                                }
                                //LLOG(LL_TRACE, "skip nalu_type %u", nalu_type);
                            }
                            p += 4 + nalu_size;
                            psize -= 4 + nalu_size;
                        } else {
                            break;
                        }
                    }
                    if (frame_cnt > 1)
                        LLOG(LL_ERROR, "%s: nalu slices not supported", client->stream->data);
                }
            } else {
                LLOG(LL_ERROR, "unsupported codec id=%hhu", ((unsigned char)data[0] & 0xf));
            }
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_NOTIFY) {
        //LLOG(LL_TRACE, "AMF0 Data Message size=%d", (int)hdr->body_size);
        if (data[0] == AMF0_TYPE_STRING) {
            int n = amf0_read_string(data, hdr->body_size, cmd_name);
            notify_handler(client, cmd_name->data, data + n, hdr->body_size - n);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_CMD) {
        double tx_id;
        if (data[0] == AMF0_TYPE_STRING) {
            int n = amf0_read_string(data, hdr->body_size, cmd_name);
            //log_info ("n={} {} {} {}", n, data[0], data[1], data[2]);
            if (data[n] == AMF0_TYPE_NUMBER) {
                n += amf0_read_number(data + n, hdr->body_size - n, &tx_id);
                command_handler(client, hdr->chunk_channel, cmd_name->data,
                    (unsigned)lroundl(tx_id), data + n, hdr->body_size - n);
            }
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF3_CMD) {
        double tx_id;
        if (data[1] == AMF0_TYPE_STRING) {
            int n = amf0_read_string (data + 1, hdr->body_size, cmd_name);
            //log_info ("n1={}", n);
            ++n; // skip one byte
            if (data[n] == AMF0_TYPE_NUMBER) {
                n += amf0_read_number (data + n, hdr->body_size - n, &tx_id);
                command_handler(client, hdr->chunk_channel, cmd_name->data,
                    (unsigned)lroundl(tx_id), data + n, hdr->body_size - n);
            }
        } else {
            LLOG(LL_WARN, "ignore %hhu %hhu amf3 cmd", data[0], data[1]);
        }
    } else {
        LLOG(LL_WARN, "unhandled ChunkTypeID %hhu", hdr->type_id);
    }
    sbuf_del(cmd_name);
}

void event_handler(rtmp_client_t *peer, rtmp_event_type_t type,
                   const char *data, int size)
{
    if (type == RTMP_EVENT_PING_REQUEST) {
        rtmp_write_pong(data, size, rtmp_write_handler, peer->chan);
    } else if (type == RTMP_EVENT_SET_BUFFER_LENGTH) {
        uint32_t stream_id = unpack_be32(data);
        uint32_t delay = unpack_be32(data + 4);
        //SendSetBufferLength (stream_id, 0);
    }
}

void notify_handler(rtmp_client_t *client, const char *cmd,
                    const char *data, int size)
{
    //LLOG(LL_TRACE, "notify '%s'", cmd);
    if (!strcmp(cmd, "|RtmpSampleAccess")) {
    } else if (!strcmp(cmd, "onMetaData")) {
    } else {

    }
}

int is_publish_status(int64_t status)
{
    return (status >= RTMP_NETSTREAM_PUBLISH_START
            && status <= RTMP_NETSTREAM_PUBLISH_IDLE);
}

void finish_requests(rtmp_client_t *client, unsigned tx_id, int64_t status)
{
    while (!list_empty(&client->request_list)) {
        rtmp_request_t *req = list_entry(client->request_list.next, rtmp_request_t, link);
        if (is_publish_status(status) && !strcmp(req->method, "publish")) {
            list_del_init(&req->link);
            if (req->ucb)
                req->ucb(client->loop, status, client->udata);
            rtmp_request_del(req);
            break;
        }

        if (req->tx_id > tx_id)
            break;
        list_del_init(&req->link);
        if (req->ucb)
            req->ucb(client->loop, (req->tx_id < tx_id) ? RTMP_SKIP_RESPONSE : status, client->udata);
        rtmp_request_del(req);
    }
}

void command_handler(rtmp_client_t *client, unsigned channel, const char *cmd,
                     unsigned tx_id, const char *data, int size)
{
    const char *p = data;
    int64_t status;
    if (!strcmp(cmd, "onStatus")) {
        p += amf0_skip(p, data + size - p);
        status = convert_to_status(p, data + size - p);
        LLOG(LL_TRACE, "onStatus: %s", get_status_text(status));

        finish_requests(client, tx_id, status);
    } else if (!strcmp(cmd, "_result")) {
        p += amf0_skip(p, data + size - p); // skip object
        status = convert_to_status(p, data + size - p);
        LLOG(LL_TRACE, "_result: %s(%d)", get_status_text(status), (int)status);

        finish_requests(client, tx_id, status);
    } else {
        LLOG(LL_WARN, "ignore cmd '%s' tx_id=%u", cmd, tx_id);
    }
}

void add_request(rtmp_client_t *client, rtmp_request_t *req)
{
    req->timestamp = zl_timestamp();
    list_add_tail(&req->link, &client->request_list);
    rtmp_write_chunk(req->channel, 0, RTMP_MESSAGE_AMF0_CMD, 0,
                     req->buf->data, req->buf->size, rtmp_write_handler, client->chan);
}

rtmp_request_t *rtmp_request_new(rtmp_client_t *client, const char *method,
                                 unsigned channel, zl_defer_cb ucb)
{
    assert(channel < RTMP_MAX_CHUNK_STREAMS);
    rtmp_request_t *req = malloc(sizeof(rtmp_request_t));
    req->method = method;
    req->channel = channel;
    req->tx_id = client->next_tx_id++;
    req->buf = sbuf_new();
    req->ucb = ucb;
    INIT_LIST_HEAD(&req->link);
    return req;
}

void rtmp_request_del(rtmp_request_t *req)
{
    sbuf_del(req->buf);
    free(req);
}

/**
 * connect(txID, {app, tcUrl});
 */
void send_connect(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "connect", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "connect");
    p += amf0_write_number(p, pend - p, req->tx_id);

    p += amf0_write_object_start(p, pend - p);
    p += amf0_write_field_name(p, pend - p, "app");
    p += amf0_write_string(p, pend - p, client->app->data);
    //p += amf0_write_field_name(p, pend - p, "flashVer");
    //p += amf0_write_string(p, pend - p, "WIN 31,0,0,122");
    //p += amf0_write_field_name(p, pend - p, "swfUrl");
    //p += amf0_write_string(p, pend - p, "http://127.0.0.1/Main.swf");
    p += amf0_write_field_name(p, pend - p, "tcUrl");
    sbuf_t *tc_url = sbuf_newf("rtmp://%s:%hu/%s", client->ip->data, client->port, client->app->data);
    p += amf0_write_string(p, pend - p, tc_url->data);
    sbuf_del(tc_url);
    //p += amf0_write_field_name(p, pend - p, "fPad");
    //p += amf0_write_boolean(p, pend - p, 0);
    p += amf0_write_field_name(p, pend - p, "capabilities");
    p += amf0_write_number(p, pend - p, 239);
    p += amf0_write_field_name(p, pend - p, "audioCodecs");
    p += amf0_write_number(p, pend - p, 3575);
    p += amf0_write_field_name(p, pend - p, "videoCodecs");
    p += amf0_write_number(p, pend - p, 252);
    p += amf0_write_field_name(p, pend - p, "videoFunction");
    p += amf0_write_number (p, pend - p, 1);
    //p += amf0_write_field_name(p, pend - p, "pageUrl");
    //p += amf0_write_string(p, pend - p, "http://127.0.0.1/");
    p += amf0_write_field_name(p, pend - p, "objectEncoding");
    p += amf0_write_number(p, pend - p, 0);
    p += amf0_write_object_end(p, pend - p);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * createStream(txID, null);
 */
void send_create_stream(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "createStream", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "createStream");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

void send_play(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "play", RTMP_SOURCE_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "play");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * releaseStream(txID, null, streamName);
 */
void send_release_stream(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "releaseStream", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, "releaseStream");
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * FCPublish(txID, null, streamName);
 */
void send_fcpublish(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "FCPublish", RTMP_SYSTEM_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, req->method);
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}

/**
 * publish(txID, null, streamName, appName);
 */
void send_publish(rtmp_client_t *client, zl_defer_cb ucb)
{
    rtmp_request_t *req = rtmp_request_new(client, "publish", RTMP_SOURCE_CHANNEL, ucb);
    const int BUF_SIZE = 1024;
    sbuf_reserve(req->buf, BUF_SIZE);
    const char *pend = req->buf->data + BUF_SIZE;
    char *p = req->buf->data;
    p += amf0_write_string(p, pend - p, req->method);
    p += amf0_write_number(p, pend - p, req->tx_id);
    p += amf0_write_null(p, pend - p);
    p += amf0_write_string(p, pend - p, client->stream->data);
    p += amf0_write_string(p, pend - p, client->app->data);
    req->buf->size = p - req->buf->data;
    add_request(client, req);
}
#if 0
void send_video(rtmp_client_t *client, uint32_t timestamp, const void *data, int size)
{
    const h264_nalu_header_t *hdr = data;
    sbuf_t *buf = sbuf_new1(size + 16);
    if (hdr->type == H264_NALU_SPS) {
        sbuf_strncpy(client->vcodec->sps_data, data, size);
    } else if (hdr->type == H264_NALU_PPS) {
        sbuf_strncpy(client->vcodec->pps_data, data, size);
    } else if (hdr->type == H264_NALU_IFRAME) {
        if (client->vcodec_changed && client->vcodec->sps_data->size >= 4 && !sbuf_empty(client->vcodec->pps_data)) {
            client->vcodec_changed = 0;

            sbuf_appendc(buf, 0x17);
            sbuf_appendc(buf, 0);   // AVC sequence header
            sbuf_appendc(buf, 0);
            sbuf_appendc(buf, 0);
            sbuf_appendc(buf, 0);
            /*AVCDecoderConfigurationRecord*/
            sbuf_appendc(buf, 0x01);
            sbuf_append2(buf, client->vcodec->sps_data->data + 1, 3);
            sbuf_appendc(buf, 0xff);
            /*sps*/
            sbuf_appendc(buf, 0xe1);
            sbuf_appendc(buf, (client->vcodec->sps_data->size >> 8) & 0xff);
            sbuf_appendc(buf, client->vcodec->sps_data->size & 0xff);
            sbuf_append(buf, client->vcodec->sps_data);
            /*pps*/
            sbuf_appendc(buf, 0x01);
            sbuf_appendc(buf, (client->vcodec->pps_data->size >> 8) & 0xff);
            sbuf_appendc(buf, client->vcodec->pps_data->size & 0xff);
            sbuf_append(buf, client->vcodec->pps_data);

            rtmp_write_chunk(RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                             timestamp, buf->data, buf->size, rtmp_write_handler, client->chan);

            sbuf_clear(buf);
            LLOG(LL_TRACE, "send AVC sequence header");
        }
        sbuf_appendc(buf, 0x17);
        sbuf_appendc(buf, 1);       // AVC NALU
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_resize(buf, buf->size + 4);
        pack_be32(sbuf_tail(buf) - 4, size);
        sbuf_append2(buf, data, size);

        rtmp_write_chunk(RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                         timestamp, buf->data, buf->size, rtmp_write_handler, client->chan);
        if (!(client->flag & RTMP_CLIENT_IN_EVENT_CB))
            update_poll_events(client);
        LLOG(LL_TRACE, "send AVC NALU KeyFrame timestamp=%u size=%d", timestamp, buf->size);

    } else {
        sbuf_appendc(buf, 0x27);
        sbuf_appendc(buf, 1);       // AVC NALU
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_appendc(buf, 0);
        sbuf_resize(buf, buf->size + 4);
        pack_be32(sbuf_tail(buf) - 4, size);
        sbuf_append2(buf, data, size);

        rtmp_write_chunk(RTMP_SOURCE_CHANNEL, 0, RTMP_MESSAGE_VIDEO,
                         timestamp, buf->data, buf->size, rtmp_write_handler, client->chan);
        if (!(client->flag & RTMP_CLIENT_IN_EVENT_CB))
            update_poll_events(client);
        //LLOG(LL_TRACE, "send AVC NALU PFrame timestamp=%u size=%d", timestamp, buf->size);
    }
    sbuf_del(buf);
}
#endif
/** Convert returned AMF0(3) object to integer text */
rtmp_status_t convert_to_status(const char *data, size_t size)
{
    if (size <= 0)
        return RTMP_INVALID_STATUS;
    sbuf_t *field_name = sbuf_new();
    sbuf_t *code = sbuf_new();
    const char *p = data;
    char type = *p++;
    rtmp_status_t status = RTMP_INVALID_STATUS;
    double n = 1.0;
    if (type == AMF0_TYPE_OBJECT) {
        while (p < data + size) {
            p += amf0_read_fieldname(p, data + size - p, field_name);
            if (!strcmp(field_name->data, "code")) {
                p += amf0_read_string(p, data + size - p, code);
                break;
            } else {
                p += amf0_skip(p, data + size - p);
            }
        }
        if (!strcmp(code->data, "NetStream.Play.Start"))
            status = RTMP_NETSTREAM_PLAY_START;
        else if (!strcmp(code->data, "NetStream.Play.Stop"))
            status = RTMP_NETSTREAM_PLAY_STOP;
        else if (!strcmp(code->data, "NetStream.Play.Failed"))
            status = RTMP_NETSTREAM_PLAY_FAILED;
        else if (!strcmp(code->data, "NetStream.Play.StreamNotFound"))
            status = RTMP_NETSTREAM_PLAY_STREAM_NOT_FOUND;
        else if (!strcmp(code->data, "NetStream.Play.Reset"))
            status = RTMP_NETSTREAM_PLAY_RESET;
        else if (!strcmp(code->data, "NetStream.Play.PublishNotify"))
            status = RTMP_NETSTREAM_PLAY_PUBLISH_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Play.UnpublishNotify"))
            status = RTMP_NETSTREAM_PLAY_UNPUBLISH_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Pause.Notify"))
            status = RTMP_NETSTREAM_PAUSE_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Unpause.Notify"))
            status = RTMP_NETSTREAM_UNPAUSE_NOTIFY;
        else if (!strcmp(code->data, "NetStream.Publish.Start"))
            status = RTMP_NETSTREAM_PUBLISH_START;
        else if (!strcmp(code->data, "NetStream.Publish.BadName"))
            status = RTMP_NETSTREAM_PUBLISH_BADNAME;
        else if (!strcmp(code->data, "NetStream.Publish.Idle"))
            status = RTMP_NETSTREAM_PUBLISH_IDLE;
        else if (!strcmp(code->data, "NetStream.Unpublish.Success"))
            status = RTMP_NETSTREAM_UNPUBLISH_SUCCESS;
        else if (!strcmp(code->data, "NetConnection.Connect.Failed"))
            status = RTMP_NETCONNECTION_FAILED;
        else if (!strcmp(code->data, "NetConnection.Connect.Closed"))
            status = RTMP_NETCONNECTION_CLOSED;
        else if (!strcmp(code->data, "NetConnection.Connect.Success"))
            status = RTMP_NETCONNECTION_SUCCESS;
        else if (!strcmp(code->data, "NetConnection.Connect.Rejected"))
            status = RTMP_NETCONNECTION_REJECTED;
        else if (!strcmp(code->data, "NetConnection.Connect.AppShutdown"))
            status = RTMP_NETCONNECTION_APP_SHUTDOWN;
        else if (!strcmp(code->data, "NetConnection.Connect.InvalidApp"))
            status = RTMP_NETCONNECTION_INVALID_APP;
    } else if (type == AMF0_TYPE_NUMBER) {
        --p;
        amf0_read_number(p, data + size - p, &n);
        status = lroundl(n);
    }
    sbuf_del(field_name);
    sbuf_del(code);
    return status;
}

const char *get_status_text(rtmp_status_t status)
{
    switch (status) {
    case RTMP_SKIP_RESPONSE:
        return "Skipped";
    case RTMP_INVALID_STATUS:
        return "Invalid";
    case RTMP_NETSTREAM_BUFFER_EMPTY:
        return "NetStream.Buffer.Empty";
    case RTMP_NETSTREAM_BUFFER_FULL:
        return "NetStream.Buffer.Full";
    case RTMP_NETSTREAM_BUFFER_FLUSH:
        return "NetStream.Buffer.Flush";
    case RTMP_NETSTREAM_PUBLISH_START:
        return "NetStream.Publish.Start";
    case RTMP_NETSTREAM_PUBLISH_BADNAME:
        return "NetStream.Publish.BadName";
    case RTMP_NETSTREAM_PUBLISH_IDLE:
        return "NetStream.Publish.Idle";
    case RTMP_NETSTREAM_UNPUBLISH_SUCCESS:
        return "NetStream.Unpublish.Success";
    case RTMP_NETSTREAM_PLAY_START:
        return "NetStream.Play.Start";
    case RTMP_NETSTREAM_PLAY_STOP:
        return "NetStream.Play.Stop";
    case RTMP_NETSTREAM_PLAY_FAILED:
        return "NetStream.Play.Failed";
    case RTMP_NETSTREAM_PLAY_STREAM_NOT_FOUND:
        return "NetStream.Play.NotFound";
    case RTMP_NETSTREAM_PLAY_RESET:
        return "NetStream.Play.Reset";
    case RTMP_NETSTREAM_PLAY_PUBLISH_NOTIFY:
        return "NetStream.Play.PublishNotify";
    case RTMP_NETSTREAM_PLAY_UNPUBLISH_NOTIFY:
        return "NetStream.Play.UnpublishNotify";
    case RTMP_NETSTREAM_PAUSE_NOTIFY:
        return "NetStream.Pause.Notify";
    case RTMP_NETSTREAM_UNPAUSE_NOTIFY:
        return "NetStream.Unpause.Notify";
    case RTMP_NETCONNECTION_CLOSED:
        return "NetConnection.Closed";
    case RTMP_NETCONNECTION_FAILED:
        return "NetConnection.Failed";
    case RTMP_NETCONNECTION_SUCCESS:
        return "NetConnection.Success";
    case RTMP_NETCONNECTION_REJECTED:
        return "NetConnection.Rejected";
    case RTMP_NETCONNECTION_APP_SHUTDOWN:
        return "NetConnection.AppShutdown";
    case RTMP_NETCONNECTION_INVALID_APP:
        return "NetConnection.InvalidApp";
    default:
        return "Unknown";
    }
}

void handshake_handler(rtmp_client_t *client)
{
    char data[RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE];
    if (client->hstate == RTMP_HS_WAIT_S1) {
        if (tcp_chan_get_read_buf_size(client->chan) < RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE)
            return;
        tcp_chan_read(client->chan, data, RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE);
        send_c2(client, &data[1]);
        client->hstate = RTMP_HS_WAIT_S2;
        /* fall through to check S2, if recv from server S0+S1+S2  */
    }
    if (client->hstate == RTMP_HS_WAIT_S2) {
        if (tcp_chan_get_read_buf_size(client->chan) < RTMP_HANDSHAKE_S2_SIZE)
            return;
        tcp_chan_read(client->chan, data, RTMP_HANDSHAKE_S2_SIZE);
        client->hstate = RTMP_HS_DONE;
        send_connect(client, NULL);
        send_create_stream(client, NULL);
        send_play(client, NULL);
    }
}

void audio_handler(rtmp_client_t *peer, int64_t timestamp, const char *data, int size)
{
    if (size <= 2)
        return;
    /**
     * 0=Linear PCM, platform endian
     * 3=Linear PCM, little endian
     * 7=G.711 A-law
     * 8=G.711 mu-law
     * 10=AAC
     */
    int sound_format = ((int)data[0] & 0xf0) >> 4;
    /**
     * 0=5.5kHZ
     * 1=11kHZ
     * 2=22kHZ
     * 3=44kHZ
     */
    int sound_rate = (data[0] & 0xc) >> 2;
    /**
     * 0=8bit sample
     * 1=16bit sample
     */
    int sound_size = (data[0] & 0x2) >> 1;
    int sound_type = (data[0] & 1); // 0=Mono, 1=Stereo
    //LLOG(LL_TRACE, "got audio timestamp=%u size=%d fmt=%d sample_rate=%d sample_size=%d channels=%d",
    //     (unsigned)timestamp, size, sound_format, sound_rate, sound_size, sound_type);

    if (sound_format == FLV_AUDIO_CODEC_PCMA) {
        ++peer->audio_counter;
        uint32_t rtp_ts = (uint32_t)(timestamp * 8);
        //LLOG(LL_TRACE, "audio ts=%ld size=%d", timestamp, size - 1);
        rtz_stream_push_audio(peer->rtz_stream, rtp_ts, data + 1, size - 1);
    }
}

void video_nalu_handler(rtmp_client_t *peer, int64_t timestamp, const char *data, int size)
{
    //LLOG(LL_TRACE, "got NALU timestamp=%u type=%02hhx size=%d",
    //     (unsigned)timestamp, data[0], size);
    long long now = zl_timestamp();
    if (peer->last_time && now - peer->last_time > 4.0f * peer->sframe_time) {
        LLOG(LL_WARN, "%s interframe delay %lld(%.0f)",
             peer->stream->data, now - peer->last_time, peer->sframe_time);
    }
    peer->last_time = now;

    unsigned nalu_type = (unsigned)data[0] & 0x1f;
    if (nalu_type != H264_NALU_IFRAME && nalu_type != H264_NALU_PFRAME)
        return;

    ++peer->video_counter;
    /*
    if (peer->audio_counter == 0) {
        if (peer->video_counter >= 2) {
            if (peer->last_audio_timestamp <= timestamp) {
                int64_t audio_pts;
                const int samples_size = 320;
                sbuf_t *sb = sbuf_new(samples_size + 1);
                memset(sb->data, 0, samples_size + 1);
                sb->size = samples_size;
                do {
                    uint32_t audio_rtp_ts = 8 * (uint32_t)peer->last_audio_timestamp;
                    //LLOG(LL_TRACE, "insert silence pts=%ld", audio_pts);
                    rtz_stream_push_audio(peer->rtz_stream, audio_rtp_ts, sb->data, sb->size);
                    push_audio(peer->srv, peer->stream->data, (uint32_t)peer->last_audio_timestamp,
                               sb->data, sb->size);
                    peer->last_audio_timestamp += 40;
                } while (peer->last_audio_timestamp <= timestamp);
                sbuf_del(sb);
            }
        }
    }
    */
    uint32_t rtp_ts = (uint32_t)(timestamp * 90);
    int key_frame = (nalu_type == H264_NALU_IFRAME);
    rtz_stream_push_video(peer->rtz_stream, rtp_ts, peer->sframe_time, key_frame, data, size);
}

void video_avc_handler(rtmp_client_t *peer, int64_t timestamp, const char *data, int size)
{
    //LLOG(LL_TRACE, "got avc.%02hhx%02hhx%02hhx audio type=%d", data[1], data[2], data[3], peer->acodec->type);
    if (peer->rtz_stream) {
        rtz_stream_set_video_codec_h264(peer->rtz_stream, data, size);

        /*
        if (peer->acodec->type == AUDIO_CODEC_PCMA) {
            uint8_t dfla[4 + FLAC_METADATA_STREAMINFO_SIZE];
            dfla[0] = 0x80; // last metadata block
            dfla[1] = 0;
            dfla[2] = 0;
            dfla[3] = FLAC_METADATA_STREAMINFO_SIZE;
            struct FLACMetadataStreamInfo stream_info;
            stream_info.min_blocksize = 320;
            stream_info.max_blocksize = 4096;
            stream_info.min_framesize = 320;
            stream_info.max_framesize = 4096000;
            stream_info.sample_rate = 8000;
            stream_info.channels = 1;
            stream_info.bits_per_sample = 16;
            stream_info.total_samples = 0;
            memset(stream_info.md5sum, 0, sizeof(stream_info.md5sum));
            pack_flac_metadata_stream_info(dfla + 4, &stream_info);
            mse_session_set_audio_codec_flac(peer->session, dfla, sizeof(dfla));
        }
        */
    }
}

void metadata_handler(rtmp_client_t *peer, const char *data, int size)
{
    const char *p = data;
    const char *pend = data + size;

    if (*p == AMF0_TYPE_OBJECT) {
        ++p;
    } else if (*p == AMF0_TYPE_ECMA_ARRAY) {
        p += 5;
    } else {
        return;
    }

    sbuf_t *name = sbuf_new();
    sbuf_t *codec_name = sbuf_new();
    double num = 0.0;
    int i = 0;
    video_codec_reset(peer->vcodec);
    audio_codec_reset(peer->acodec);
    while (p < pend) {
        p += amf0_read_fieldname(p, pend - p, name);
        //LLOG(LL_TRACE, "%s", name->data);
        if (!strcmp(name->data, "width")) {
            p += amf0_read_number(p, pend - p, &num);
            peer->vcodec->width = lroundl(num);
        } else if (!strcmp(name->data, "height")) {
            p += amf0_read_number(p, pend - p, &num);
            peer->vcodec->height = lroundl(num);
        } else if (!strcmp(name->data, "framerate")) {
            p += amf0_read_number(p, pend - p, &num);
            peer->vcodec->frame_rate = lroundl(num);
            if (peer->vcodec->frame_rate > 0 && !peer->sframe_time)
                peer->sframe_time = 1000.0f / peer->vcodec->frame_rate;
            //LLOG(LL_TRACE, "framerate=%d", peer->vcodec->frame_rate);
        } else if (!strcmp(name->data, "videocodecid")) {
            if (p[0] == AMF0_TYPE_STRING) {
                p += amf0_read_string(p, pend - p, codec_name);
                if (!strcmp(codec_name->data, "avc1")) {
                    peer->vcodec->type = VIDEO_CODEC_H264;
                    peer->vcodec->time_base = 1000;
                }
            } else if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                i = lroundl(num);
                if (i == FLV_VIDEO_CODEC_H264) {
                    peer->vcodec->type = VIDEO_CODEC_H264;
                    peer->vcodec->time_base = 1000;
                }
            }
        } else if (!strcmp(name->data, "audiocodecid")) {
            if (p[0] == AMF0_TYPE_STRING) {
                p += amf0_read_string(p, pend - p, codec_name);
                if (!strcmp(codec_name->data, "mp4a")) {
                    peer->acodec->type = AUDIO_CODEC_AAC;
                }
            } else if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                i = lroundl(num);
                //LLOG(LL_TRACE, "audiocodecid=%d", i);
                if (i == FLV_AUDIO_CODEC_PCMA)
                    peer->acodec->type = AUDIO_CODEC_PCMA;
                else if (i == FLV_AUDIO_CODEC_PCMU)
                    peer->acodec->type = AUDIO_CODEC_PCMU;
                else if (i == FLV_AUDIO_CODEC_AAC)
                    peer->acodec->type = AUDIO_CODEC_AAC;
            }
        } else if (!strcmp(name->data, "audiosamplerate")) {
            if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                peer->acodec->sample_rate = lroundl(num);
            }
        } else if (!strcmp(name->data, "audiosamplesize")) {
            if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                peer->acodec->bits_per_sample = lroundl(num);
            }
        } else if (!strcmp(name->data, "stereo")) {
            if (p[0] == AMF0_TYPE_BOOLEAN) {
                p += amf0_read_boolean(p, pend - p, &i);
                peer->acodec->num_channels = i ? 2 : 1;
            }
        } else if (!strcmp(name->data, "videotime")) {
            if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                //LLOG(LL_TRACE, "videotime=%.0lf", num);

                rtz_stream_update_videotime(peer->rtz_stream, num);
            }
        } else if (!strcmp(name->data, "systemtime")) {
            if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                //LLOG(LL_TRACE, "systemtime=%.0lf", num);
            }
        } else if (!strcmp(name->data, "duration")) {
            if (p[0] == AMF0_TYPE_NUMBER) {
                p += amf0_read_number(p, pend - p, &num);
                peer->duration = num;
                //LLOG(LL_TRACE, "%s duration=%.2lf",
                //     peer->stream->data, peer->duration);
            }
        } else {
            int type = *p;
            p += amf0_skip(p, pend - p);
            if (*p == AMF0_TYPE_OBJECT_END_MARKER)
                break;
        }
    }
    sbuf_del(name);
    sbuf_del(codec_name);
}

void rtmp_write_handler(const void *data, int size, void *udata)
{
    tcp_chan_t *chan = udata;
    tcp_chan_write(chan, data, size);
}
