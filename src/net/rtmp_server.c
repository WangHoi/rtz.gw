#include "rtmp_server.h"
#include "event_loop.h"
#include "net_util.h"
#include "log.h"
#include "cbuf.h"
#include "sbuf.h"
#include "list.h"
#include "pack_util.h"
#include "rtz_server.h"
#include "media/rtp_types.h"
#include "media/h26x.h"
#include "media/flac_util.h"
#include "media/codec_types.h"
#include "timestamp.h"
#include "net/tcp_chan.h"
#include "rtmp_handshake.h"
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <math.h>
#include <inttypes.h>

enum {
	RTMP_PEER_RCV_BUF_SIZE = (1 << 16),
	RTMP_PEER_SND_BUF_SIZE = (1 << 16),
	MAX_RTMP_HEADER_SIZE = 1024,
};

enum rtmp_client_flag {
    RTMP_PEER_IN_EVENT_CB = 1,
    RTMP_PEER_ERROR = 2,
    RTMP_PEER_EOF = 4,
    RTMP_PEER_PUBLISH = 8,
    RTMP_PEER_PLAY = 16,
    RTMP_PEER_IFRAME_READY = 32,
};

typedef enum rtmp_parse_state_t {
    RTMP_PARSE_INIT,
    RTMP_PARSE_CHUNK_HEADER,
    RTMP_PARSE_CHUNK_BODY,
    NUM_RTMP_PARSE_STATES,
} rtmp_parse_state_t;

typedef enum rtmp_handshake_state_t {
    RTMP_HS_INIT,
    RTMP_HS_WAIT_C1,
    RTMP_HS_WAIT_C2,
    RTMP_HS_DONE,
} rtmp_handshake_state_t;

typedef struct rtmp_response_t {
    rtmp_peer_t *peer;
    long long timestamp;
    const char *method;
    unsigned char channel;
    unsigned tx_id;
    sbuf_t *buf;
    struct list_head link;
} rtmp_response_t;

enum rtmp_parse_state {
	RTMP_PARSE_HEADER,
	RTMP_PARSE_BODY,
};

struct rtmp_server_t {
	zl_loop_t *loop;
    tcp_srv_t *tcp_srv;
    rtz_server_t *rtz_srv;
    struct list_head peer_list;
};

struct rtmp_peer_t {
    zl_loop_t *loop;
	rtmp_server_t *srv;
    tcp_chan_t *chan;
    sbuf_t *chunk_body[RTMP_MAX_CHUNK_STREAMS];

    sbuf_t *app;
    sbuf_t *tc_url;
    sbuf_t *stream;
    rtz_stream_t *rtz_stream;

    tsc_t *video_tsc;
    tsc_t *audio_tsc;
    int64_t last_audio_timestamp;
    uint64_t video_counter;
    uint64_t audio_counter;

    video_codec_t *vcodec;
    audio_codec_t *acodec;

    double duration;
    uint16_t sframe_time;       /* smoothed 1000/fps */
    int64_t last_video_ts;

    sbuf_t *sps;
    sbuf_t *pps;

    rtmp_handshake_state_t hstate;
    rtmp_parse_state_t pstate;
    rtmp_chunk_t last_chunks[RTMP_MAX_CHUNK_STREAMS];
    unsigned next_tx_id;
    rtmp_chunk_t cur_chunk;
    int recv_body_size_limit;
    char header[RTMP_MAX_CHUNK_HEADER_SIZE];

	int flag;
    struct list_head link;

    long long last_time;
};

static void accept_handler(tcp_srv_t *srv, tcp_chan_t *chan, void *udata);
static void peer_data_handler(tcp_chan_t *peer, void *udata);
static void peer_error_handler(tcp_chan_t *peer, int status, void *udata);

static void handshake_handler(rtmp_peer_t *peer);
static void session_handler(rtmp_peer_t *peer);
static void chunk_handler(rtmp_peer_t *peer);
static void audio_handler(rtmp_peer_t *peer, int64_t timestamp,
                          const char *data, int size);
static void video_nalu_handler(rtmp_peer_t *peer, int64_t timestamp,
                               const char *data, int size);
static void video_avc_handler(rtmp_peer_t *peer, int64_t timestamp,
                              const char *data, int size);
static void notify_handler(rtmp_peer_t *peer, const char *cmd,
                           const char *data, int size);
static void event_handler(rtmp_peer_t *peer, rtmp_event_type_t type,
                          const char *data, int size);
static void command_handler(rtmp_peer_t *peer, unsigned channel, const char *cmd,
                            unsigned tx_id, const char *data, int size);
static void metadata_handler(rtmp_peer_t *peer, const char *data, int size);
static void connect_handler(rtmp_peer_t *peer, const char *data, int size,
                            sbuf_t *app, sbuf_t *tc_url);
static void send_s012(rtmp_peer_t *peer, const char *c1);

static rtmp_peer_t *rtmp_peer_new(rtmp_server_t *srv, tcp_chan_t *chan);
static void rtmp_peer_del(rtmp_peer_t *peer);

static rtmp_response_t *rtmp_response_new(rtmp_peer_t *peer, const char *method,
                                          unsigned channel);
static void rtmp_response_del(rtmp_response_t *resp);
static void add_response(rtmp_peer_t *peer, uint32_t timestamp, rtmp_message_type_t type,
                         uint32_t stream_id, rtmp_response_t *response);
static void add_cmd_response(rtmp_peer_t *peer, rtmp_response_t *response);
static void add_event_response(rtmp_peer_t *peer, rtmp_response_t *response);
static void send_connect_result(rtmp_peer_t *peer, unsigned tx_id);
static void send_stream_event(rtmp_peer_t *peer, rtmp_event_type_t event);
static void send_create_stream_result(rtmp_peer_t *peer, unsigned tx_id);
static void send_on_status(rtmp_peer_t *peer, unsigned tx_id, const char *status);
static void send_notify(rtmp_peer_t *peer, const char *event, const void *data, int size);
static void rtmp_server_cron(zl_loop_t *loop, int fd, uint64_t expires, void* udata);

static void rtmp_write_handler(const void *data, int size, void *udata);
static void set_video_codec_h264(rtmp_server_t *srv, const char *stream_name,
                                 uint32_t timestamp, const char *data, int size);
static void push_video(rtmp_server_t *srv, const char *stream_name, uint32_t timestamp,
                       int key_frame, const void *data, int size);
static void push_audio(rtmp_server_t *srv, const char *stream_name, uint32_t timestamp,
                       const void *data, int size);

rtmp_server_t *rtmp_server_new(zl_loop_t* loop, rtz_server_t *mse_srv)
{
    assert(rtz_server_get_loop(mse_srv) == loop);
	rtmp_server_t* srv;
	int ret;
	srv = malloc(sizeof(rtmp_server_t));
	if (srv == NULL)
		return NULL;
    memset(srv, 0, sizeof(rtmp_server_t));
	srv->loop = loop;
    srv->tcp_srv = tcp_srv_new(loop);
    srv->rtz_srv = mse_srv;
    INIT_LIST_HEAD(&srv->peer_list);
	return srv;
}

int rtmp_server_bind(rtmp_server_t *srv, unsigned short port)
{
    return tcp_srv_bind(srv->tcp_srv, NULL, port);
}

int rtmp_server_start(rtmp_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, accept_handler, srv);
    return tcp_srv_listen(srv->tcp_srv);
}

void rtmp_server_stop(rtmp_server_t *srv)
{

}

void rtmp_server_del(rtmp_server_t *srv)
{
    rtmp_peer_t *p, *tmp;
    list_for_each_entry_safe(p, tmp, &srv->peer_list, link) {
        rtmp_peer_del(p);
    }
    tcp_srv_del(srv->tcp_srv);
	free(srv);
}

void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    rtmp_server_t *srv = udata;
    rtmp_peer_t *peer = rtmp_peer_new(srv, chan);
    if (!peer) {
        LLOG(LL_ERROR, "rtmp_peer_new error.");
        return;
    }
    peer->hstate = RTMP_HS_WAIT_C1;
    tcp_chan_set_cb(peer->chan, peer_data_handler, NULL, peer_error_handler, peer);
}
/*
void accept_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
	rtmp_server_t *srv = udata;
	struct sockaddr_in saddr;
	socklen_t saddr_len = sizeof(struct sockaddr_in);
	int ret;
	int peer_fd;
    rtmp_peer_t *peer;
again:
	peer_fd = accept4(srv->fd, (struct sockaddr*)&saddr, &saddr_len, SOCK_NONBLOCK | SOCK_CLOEXEC);
	if (peer_fd == -1) {
		if (errno == EINTR)
			goto again;
		if (errno != EAGAIN)
			LLOG(LL_ERROR, "accept error: %s", strerror(errno));
		return;
	}
    set_tcp_nodelay(peer_fd, 1);
	peer = rtmp_peer_new(srv, peer_fd);
	if (!peer) {
		LLOG(LL_ERROR, "rtmp_peer_new error.");
        close(peer_fd);
		return;
	}
    peer->eevents = EPOLLIN;
    peer->hstate = RTMP_HS_WAIT_C1;
    zl_fd_ctl(peer->srv->loop, EPOLL_CTL_ADD, peer->fd, peer->eevents, &peer_fd_event_handler, peer);
    LLOG(LL_TRACE, "new fd %d", peer_fd);
}

void peer_fd_event_handler(zl_loop_t *loop, int fd, uint32_t events, void *udata)
{
    rtmp_peer_t *peer = udata;
    peer->flag |= RTMP_PEER_IN_EVENT_CB;
    if (peer->hstate != RTMP_HS_DONE)
        handshake_handler(peer, fd, events);
    else
        session_handler(peer, fd, events);
    update_poll_events(peer);
    if (peer->flag & RTMP_PEER_ERROR)
        error_handler(peer, -EINVAL);
    peer->flag &= ~RTMP_PEER_IN_EVENT_CB;
    if (peer->flag & (RTMP_PEER_ERROR | RTMP_PEER_EOF))
        rtmp_peer_del(peer);
}
*/

void peer_data_handler(tcp_chan_t *chan, void *udata)
{
    rtmp_peer_t *peer = udata;
    peer->flag |= RTMP_PEER_IN_EVENT_CB;
    if (peer->hstate != RTMP_HS_DONE)
        handshake_handler(peer);
    if (peer->hstate == RTMP_HS_DONE)
        session_handler(peer);
    peer->flag &= ~RTMP_PEER_IN_EVENT_CB;
    if (peer->flag & (RTMP_PEER_ERROR | RTMP_PEER_EOF))
        rtmp_peer_del(peer);
}

void peer_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    LLOG(LL_TRACE, "rtmp_peer %p error %d", udata, status);
    rtmp_peer_t *peer = udata;
    rtmp_peer_del(peer);
}

rtmp_peer_t *rtmp_peer_new(rtmp_server_t *srv, tcp_chan_t *chan)
{
	rtmp_peer_t *peer = malloc(sizeof(struct rtmp_peer_t));
	if (peer == NULL)
		return NULL;
    LLOG(LL_TRACE, "rtmp_peer_new %p", peer);
    memset(peer, 0, sizeof(rtmp_peer_t));
    peer->loop = srv->loop;
	peer->srv = srv;
	peer->chan = chan;
    peer->app = sbuf_new();
    peer->tc_url = sbuf_new();
    peer->stream = sbuf_new();
    peer->hstate = RTMP_HS_INIT;
    peer->pstate = RTMP_PARSE_INIT;
    peer->recv_body_size_limit = RTMP_DEFAULT_CHUNK_BODY_SIZE;
    peer->vcodec = video_codec_new();
    peer->acodec = audio_codec_new();
    peer->sps = sbuf_new();
    peer->pps = sbuf_new();
    peer->video_tsc = tsc_new(32, 4000, 40);
    peer->audio_tsc = tsc_new(32, 4000, 40);
    list_add(&peer->link, &srv->peer_list);
	return peer;
}

void rtmp_peer_del(rtmp_peer_t *peer)
{
    LLOG(LL_TRACE, "rtmp_peer_del %p", peer);
    if (peer->rtz_stream) {
        rtz_stream_del(peer->rtz_stream);
        peer->rtz_stream = NULL;
    }
    if ((peer->flag & RTMP_PEER_PUBLISH) && !sbuf_empty(peer->stream)) {
        rtmp_peer_t *p, *tmp;
        list_for_each_entry_safe(p, tmp, &peer->srv->peer_list, link) {
            if ((p->flag & RTMP_PEER_PLAY)
                && p != peer
                && !strcmp(peer->stream->data, p->stream->data)) {
                rtmp_peer_del(p);
            }
            
        }
    }
    int i;
    for (i = 0; i < RTMP_MAX_CHUNK_STREAMS; ++i)
        if (peer->chunk_body[i])
            sbuf_del(peer->chunk_body[i]);
    sbuf_del(peer->app);
    sbuf_del(peer->tc_url);
    sbuf_del(peer->stream);
    tcp_chan_close(peer->chan, 0);
    sbuf_del(peer->sps);
    sbuf_del(peer->pps);
    video_codec_del(peer->vcodec);
    audio_codec_del(peer->acodec);
    tsc_del(peer->video_tsc);
    tsc_del(peer->audio_tsc);
    list_del(&peer->link);
    free(peer);
}

void rtmp_server_cron(zl_loop_t *loop, int fd, uint64_t expires, void* udata)
{
	LLOG(LL_TRACE, "rtmp server cron expires=%lu", (long)expires);
	rtmp_server_t *srv = udata;
}

void handshake_handler(rtmp_peer_t *peer)
{
    int n;
    char data[RTMP_HANDSHAKE_C0_SIZE + RTMP_HANDSHAKE_C1_SIZE];
    if (peer->hstate == RTMP_HS_WAIT_C1) {
        if (tcp_chan_get_read_buf_size(peer->chan) < RTMP_HANDSHAKE_C0_SIZE + RTMP_HANDSHAKE_C1_SIZE)
            return;
        tcp_chan_read(peer->chan, data, RTMP_HANDSHAKE_C0_SIZE + RTMP_HANDSHAKE_C1_SIZE);
        send_s012(peer, &data[1]);
        peer->hstate = RTMP_HS_WAIT_C2;
    } else if (peer->hstate == RTMP_HS_WAIT_C2) {
        if (tcp_chan_get_read_buf_size(peer->chan) < RTMP_HANDSHAKE_C2_SIZE)
            return;
        tcp_chan_read(peer->chan, data, RTMP_HANDSHAKE_C2_SIZE);
        peer->hstate = RTMP_HS_DONE;
    }
}

void send_s012(rtmp_peer_t *peer, const char *c1)
{
    char data[RTMP_HANDSHAKE_S0_SIZE + RTMP_HANDSHAKE_S1_SIZE + RTMP_HANDSHAKE_S2_SIZE];
    char *p = data;

    rtmp_hs_t *hs = rtmp_hs_new();
    rtmp_hs_set_c1(hs, c1);
    *p++ = 3; /* Version */
    memcpy(p, rtmp_hs_generate_s1(hs), RTMP_HANDSHAKE_S1_SIZE);
    p += RTMP_HANDSHAKE_S1_SIZE;
    memcpy(p, rtmp_hs_generate_s2(hs), RTMP_HANDSHAKE_S2_SIZE);
    p += RTMP_HANDSHAKE_S2_SIZE;
    rtmp_hs_del(hs);
    tcp_chan_write(peer->chan, data, sizeof(data));
}

void session_handler(rtmp_peer_t *peer)
{
    //LLOG(LL_TRACE, "read_buf size=%d", tcp_chan_get_read_buf_size(peer->chan));
    while (!tcp_chan_read_buf_empty(peer->chan)) {
        if (peer->pstate == RTMP_PARSE_INIT) {
            peer->pstate = RTMP_PARSE_CHUNK_HEADER;
        } else if (peer->pstate == RTMP_PARSE_CHUNK_HEADER) {
            unsigned char fmt = rtmp_chunk_header_fmt(tcp_chan_peekc(peer->chan));
            int hdr_len = rtmp_chunk_header_len(fmt);
            int buf_len = tcp_chan_get_read_buf_size(peer->chan);
            if (fmt == 0 || fmt == 1 || fmt == 2) {
                if (buf_len < 4)
                    break;
                uint8_t tmp_buf[4];
                tcp_chan_peek(peer->chan, tmp_buf, 4);
                if (unpack_be24(tmp_buf + 1) == 0xffffff) {
                    peer->cur_chunk.ext_timestamp_present = 1;
                    hdr_len += 4;
                } else {
                    peer->cur_chunk.ext_timestamp_present = 0;
                }
            } else if (fmt == 3) {
                if (peer->cur_chunk.ext_timestamp_present)
                    hdr_len += 4;
            }
            if (buf_len < hdr_len)
                break;

            tcp_chan_read(peer->chan, peer->header, hdr_len);
            peer->cur_chunk.chunk_channel = rtmp_chunk_channel(peer->header[0]);
            if (fmt == 0) {
                if (peer->cur_chunk.ext_timestamp_present) {
                    peer->cur_chunk.timestamp = unpack_be32(peer->header + RTMP_CHUNK_HEADER_SIZE_FMT0);
                } else {
                    peer->cur_chunk.timestamp = unpack_be24(&peer->header[1]);
                }
                peer->cur_chunk.body_size = unpack_be24(&peer->header[4]);
                peer->cur_chunk.type_id = (unsigned char)peer->header[7];
                peer->cur_chunk.msg_stream_id = unpack_le32 (&peer->header[8]);
                memcpy(&peer->last_chunks[peer->cur_chunk.chunk_channel],
                        &peer->cur_chunk, sizeof(rtmp_chunk_t));
            } else if (fmt == 1) {
                if (peer->cur_chunk.ext_timestamp_present) {
                    peer->cur_chunk.timestamp_delta = unpack_be32(peer->header + RTMP_CHUNK_HEADER_SIZE_FMT1);
                } else {
                    peer->cur_chunk.timestamp_delta = unpack_be24(&peer->header[1]);
                }
                peer->cur_chunk.body_size = unpack_be24(&peer->header[4]);
                peer->cur_chunk.type_id = (unsigned char)peer->header[7];
                peer->cur_chunk.timestamp = peer->last_chunks[peer->cur_chunk.chunk_channel].timestamp
                    + peer->cur_chunk.timestamp_delta;
                memcpy(&peer->last_chunks[peer->cur_chunk.chunk_channel],
                        &peer->cur_chunk, sizeof(rtmp_chunk_t));
            } else if (fmt == 2) {
                rtmp_chunk_t *lc = &peer->last_chunks[peer->cur_chunk.chunk_channel];
                if (peer->cur_chunk.ext_timestamp_present) {
                    peer->cur_chunk.timestamp_delta = unpack_be32(peer->header + RTMP_CHUNK_HEADER_SIZE_FMT2);
                } else {
                    peer->cur_chunk.timestamp_delta = unpack_be24(&peer->header[1]);
                }
                peer->cur_chunk.body_size = lc->body_size;
                peer->cur_chunk.type_id = lc->type_id;
                peer->cur_chunk.timestamp = lc->timestamp + peer->cur_chunk.timestamp_delta;
                memcpy(&peer->last_chunks[peer->cur_chunk.chunk_channel],
                        &peer->cur_chunk, sizeof(rtmp_chunk_t));
            } else {
                rtmp_chunk_t *lc = &peer->last_chunks[peer->cur_chunk.chunk_channel];
                peer->cur_chunk.body_size = lc->body_size;
                peer->cur_chunk.type_id = lc->type_id;
                peer->cur_chunk.timestamp = lc->timestamp;
            }
            //LLOG(LL_TRACE, "fmt=%d chan=%d cur_chunk.body_size=%d",
            //    (int)fmt, (int)peer->cur_chunk.chunk_channel, peer->cur_chunk.body_size);
            //LLOG(LL_TRACE, "header chan=%hhu fmt=%hhu timestamp=%u hdr_len=%d body_size=%d",
            //     peer->cur_chunk.chunk_channel, fmt, peer->cur_chunk.timestamp, hdr_len,
            //     peer->cur_chunk.body_size);
            peer->pstate = RTMP_PARSE_CHUNK_BODY;
        } else if (peer->pstate == RTMP_PARSE_CHUNK_BODY) {
            sbuf_t *chunk_body = peer->chunk_body[peer->cur_chunk.chunk_channel];
            if (!chunk_body)
                chunk_body = peer->chunk_body[peer->cur_chunk.chunk_channel] = sbuf_new();
            int n = peer->cur_chunk.body_size - chunk_body->size;
            if (n < 0) {
                LLOG(LL_ERROR, "%s parse error, body_size=%d chunk_size=%d.",
                     peer->stream->data, peer->cur_chunk.body_size, chunk_body->size);
                peer->flag |= RTMP_PEER_ERROR;
                break;
            }
            if (n > tcp_chan_get_read_buf_size(peer->chan))
                n = tcp_chan_get_read_buf_size(peer->chan);
            int m = peer->recv_body_size_limit - (chunk_body->size % peer->recv_body_size_limit);
            if (n > m)
                n = m;
            int old_size = chunk_body->size;
            sbuf_resize(chunk_body, old_size + n);
            tcp_chan_read(peer->chan, chunk_body->data + old_size, n);
            //LLOG(LL_TRACE, "%d %d %d", peer->cur_chunk.body_size, chunk_body->size, peer->last_chunks[peer->cur_chunk.chunk_channel].body_size);
            if (chunk_body->size % peer->recv_body_size_limit == 0) {
                //LLOG(LL_TRACE, "  chunk size %d limit reached, total %d", peer->chunk_body->size, peer->cur_chunk.body_size);
                peer->pstate = RTMP_PARSE_INIT;
            }
            if (chunk_body->size == peer->cur_chunk.body_size) {
                //log_info ("buffer_size={} hdr_size={} body_size={}", _buffer.size (), _chunk_header.header_size, _chunk_header.body_size);
                chunk_handler(peer);
                sbuf_clear(chunk_body);
                peer->pstate = RTMP_PARSE_INIT;
            }
        }
    }
}

void chunk_handler(rtmp_peer_t *peer)
{
    rtmp_chunk_t *hdr = &peer->cur_chunk;
    char *data = peer->chunk_body[hdr->chunk_channel]->data;
    int size = peer->chunk_body[hdr->chunk_channel]->size;
    sbuf_t *cmd_name = sbuf_new();
    if (hdr->type_id == RTMP_MESSAGE_SET_CHUNK_SIZE) {
        if (hdr->body_size == 4) {
            uint32_t chunk_size = unpack_be32(data) & 0x7fffffff;
            //LLOG(LL_TRACE, "SetChunkSize %d", (int)chunk_size);
            peer->recv_body_size_limit = chunk_size;
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
            event_handler(peer, etype, edata, esize);
            LLOG(LL_TRACE, "UserControl event_type=%d event_size=%d", (int)etype, (int)esize);
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
        int64_t timestamp = tsc_timestamp(peer->audio_tsc, hdr->timestamp);
        audio_handler(peer, timestamp, data, size);
    } else if (hdr->type_id == RTMP_MESSAGE_VIDEO) {
        //LLOG(LL_TRACE, "video size=%d data=%02hhx%02hhx%02hhx%02hhx", (int)size, data[0], data[1], data[2], data[3]);
        int64_t timestamp = tsc_timestamp(peer->video_tsc, hdr->timestamp);

        /* Update frame_time */
        int64_t frame_time = timestamp - peer->last_video_ts;
        if (0 < frame_time && frame_time < 1000) {
            if (peer->sframe_time)
                peer->sframe_time = (frame_time + 3 * peer->sframe_time) / 4;
            else
                peer->sframe_time = frame_time;
        }
        peer->last_video_ts = timestamp;

        if (size > 5) {
            if ((data[0] & 0xf) == 7) { // AVC Codec
                char *p = data + 5;
                int psize = size - 5;
                if (data[1] == 0) {
                    video_avc_handler(peer, timestamp, p, psize);
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
                                video_nalu_handler(peer, timestamp, p + 4, nalu_size);
                            } else {
                                if (nalu_type == 7) {
                                    sbuf_strncpy(peer->sps, p + 4, nalu_size);
                                } else if (nalu_type == 8) {
                                    sbuf_strncpy(peer->pps, p + 4, nalu_size);
                                    if (!sbuf_empty(peer->sps) && !sbuf_empty(peer->pps)) {
                                        sbuf_t *avc = make_h264_decoder_config_record(peer->sps->data, peer->sps->size,
                                                                                      peer->pps->data, peer->pps->size);
                                        video_avc_handler(peer, timestamp, avc->data, avc->size);
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
                        LLOG(LL_ERROR, "%s: nalu slices not supported", peer->stream->data);
                }
            } else {
                LLOG(LL_ERROR, "unsupported codec id=%hhu", ((unsigned char)data[0] & 0xf));
            }
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_NOTIFY) {
        //LLOG(LL_TRACE, "AMF0 Data Message size=%d", (int)hdr->body_size);
        if (data[0] == AMF0_TYPE_STRING) {
            int n = amf0_read_string(data, hdr->body_size, cmd_name);
            notify_handler(peer, cmd_name->data, data + n, hdr->body_size - n);
        }
    } else if (hdr->type_id == RTMP_MESSAGE_AMF0_CMD) {
        double tx_id;
        if (data[0] == AMF0_TYPE_STRING) {
            int n = amf0_read_string(data, hdr->body_size, cmd_name);
            //log_info ("n={} {} {} {}", n, data[0], data[1], data[2]);
            if (data[n] == AMF0_TYPE_NUMBER) {
                n += amf0_read_number(data + n, hdr->body_size - n, &tx_id);
                command_handler(peer, hdr->chunk_channel, cmd_name->data,
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
                command_handler(peer, hdr->chunk_channel, cmd_name->data,
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

void audio_handler(rtmp_peer_t *peer, int64_t timestamp, const char *data, int size)
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
        push_audio(peer->srv, peer->stream->data, (uint32_t)timestamp, data + 1, size - 1);
    }
}

void video_nalu_handler(rtmp_peer_t *peer, int64_t timestamp, const char *data, int size)
{
    //LLOG(LL_TRACE, "got nalu timestamp=%u type=%02hhx size=%d",
    //     (unsigned)timestamp, data[0], size);
    long long now = zl_timestamp();
    if (peer->last_time && now - peer->last_time > 2 * peer->sframe_time + peer->sframe_time / 2)
        LLOG(LL_WARN, "%s interframe delay %lld(%hu)",
             peer->stream->data, now - peer->last_time, peer->sframe_time);
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
    push_video(peer->srv, peer->stream->data, (uint32_t)timestamp, key_frame, data, size);
}

void video_avc_handler(rtmp_peer_t *peer, int64_t timestamp, const char *data, int size)
{
    //LLOG(LL_TRACE, "got avc.%02hhx%02hhx%02hhx audio type=%d", data[1], data[2], data[3], peer->acodec->type);
    if (peer->rtz_stream) {
        rtz_stream_set_video_codec_h264(peer->rtz_stream, data, size);
        set_video_codec_h264(peer->srv, peer->stream->data, (uint32_t)timestamp, data, size);

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

void metadata_handler(rtmp_peer_t *peer, const char *data, int size)
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
                peer->sframe_time = 1000 / peer->vcodec->frame_rate;
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

void connect_handler(rtmp_peer_t *peer, const char *data, int size,
                     sbuf_t *app, sbuf_t *tc_url)
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
    while (p < pend) {
        p += amf0_read_fieldname(p, pend - p, name);
        //LLOG(LL_TRACE, "%s", name->data);
        if (!strcasecmp(name->data, "app")) {
            if (p < pend && *p == AMF0_TYPE_STRING && app) {
                p += amf0_read_string(p, pend - p, app);
                const char *q1 = strchr(app->data + 1, '?');
                const char *q2 = strchr(app->data + 1, '/');
                const char *q;
                if (!q1)
                    q = q2;
                else if (!q2)
                    q = q1;
                else
                    q = (q1 < q2) ? q1 : q2;
                if (q)
                    sbuf_resize(app, q - app->data);
            } else {
                p += amf0_skip(p, pend - p);
            }
        } else if (!strcasecmp(name->data, "tcUrl")) {
            if (p < pend && *p == AMF0_TYPE_STRING && tc_url) {
                p += amf0_read_string(p, pend - p, tc_url);
            } else {
                p += amf0_skip(p, pend - p);
            }
        } else {
            int type = *p;
            p += amf0_skip(p, pend - p);
            if (*p == AMF0_TYPE_OBJECT_END_MARKER)
                break;
        }
    }
    sbuf_del(name);
}

void notify_handler(rtmp_peer_t *peer, const char *cmd, const char *data, int size)
{
    //LLOG(LL_TRACE, "notify '%s' size=%d", cmd, size);
    const char *p = data;
    const char *pend = data + size;

    if (peer->flag & RTMP_PEER_PUBLISH) {
        rtmp_peer_t *player, *tmp;
        list_for_each_entry_safe(player, tmp, &peer->srv->peer_list, link) {
            if ((player->flag & RTMP_PEER_PLAY) && !strcmp(player->stream->data, peer->stream->data)) {
                //LLOG(LL_TRACE, "forward %s", cmd);
                send_notify(player, cmd, data, size);
            }
        }
    }


    if (!strcmp(cmd, "|RtmpSampleAccess")) {
    } else if (!strcmp(cmd, "onMetaData")) {
    } else if (!strcmp(cmd, "@setDataFrame")) {
        sbuf_t *name = sbuf_new();
        if (*p == AMF0_TYPE_STRING) {
            p += amf0_read_string(p, pend - p, name);
            if (!strcmp(name->data, "onMetaData"))
                metadata_handler(peer, p, pend - p);
        }
        sbuf_del(name);
    } else {

    }
}

/**
 * Handle AMF0 command, with 'cmd_name' and 'tx_id' prefix stripped
 */
void command_handler(rtmp_peer_t *peer, unsigned channel, const char *cmd,
                     unsigned tx_id, const char *data, int size)
{
    //LLOG(LL_TRACE, "cmd=%s tx_id=%u", cmd, tx_id);
    const char *p = data;
    const char *pend = data + size;
    int64_t status;
    if (!strcmp(cmd, "connect")) {
        connect_handler(peer, data, size, peer->app, peer->tc_url);
        LLOG(LL_INFO, "connect_handler app='%s' tcUrl='%s'",
             peer->app->data, peer->tc_url->data);
        send_connect_result(peer, tx_id);
    } else if (!strcmp(cmd, "createStream")) {
        send_create_stream_result(peer, tx_id);
    } else if (!strcmp(cmd, "releaseStream")) {
        /*ignore*/
    } else if (!strcmp(cmd, "publish")) {
        peer->flag |= RTMP_PEER_PUBLISH;
        p += amf0_skip(data, pend - p);
        if (p[0] == AMF0_TYPE_STRING) {
            p += amf0_read_string(p, pend - p, peer->stream);
        } else if (p[0] == AMF0_TYPE_NUMBER) {
            double num = 0.0;
            p += amf0_read_number(p, pend - p, &num);
            sbuf_printf(peer->stream, "%.0lf", num);
        } else {
            LLOG(LL_WARN, "publish: use default stream_name 'stream'");
            sbuf_strcpy(peer->stream, "stream");
            p += amf0_skip(p, pend - p);
        }
        if (p[0] == AMF0_TYPE_STRING) {
            p += amf0_read_string(p, pend - p, peer->app);
        } else {
            LLOG(LL_WARN, "publish: use default app 'live'");
            sbuf_strcpy(peer->app, "live");
            p += amf0_skip(p, pend - p);
        }
        rtz_stream_t *old_stream = rtz_stream_get(peer->srv->rtz_srv, peer->stream->data);
        if (old_stream || peer->rtz_stream) {
            LLOG(LL_ERROR, "publish error tcUrl='%s' stream_name='%s', "
                 "exist rtz_stream_t %p, peer rtz_stream_t %p",
                 peer->tc_url->data, peer->stream->data, old_stream, peer->rtz_stream);
            send_on_status(peer, peer->next_tx_id++, "NetStream.Publish.BadName");
        } else {
            peer->rtz_stream = rtz_stream_new(peer->srv->rtz_srv, peer->stream->data);
            LLOG(LL_TRACE, "publish tcUrl='%s' stream_name='%s'",
                 peer->tc_url->data, peer->stream->data);
            send_on_status(peer, peer->next_tx_id++, "NetStream.Publish.Start");
        }
    } else if (!strcmp(cmd, "play")) {
        p += amf0_skip(data, pend - p);
        if (p[0] == AMF0_TYPE_STRING) {
            p += amf0_read_string(p, pend - p, peer->stream);
        } else {
            p += amf0_skip(p, pend - p);
        }
        LLOG(LL_TRACE, "play stream_name='%s'", peer->stream->data);
        peer->flag |= RTMP_PEER_PLAY;
        rtz_stream_t *stream = rtz_stream_get(peer->srv->rtz_srv, peer->stream->data);
        send_stream_event(peer, RTMP_EVENT_STREAM_BEGIN);
        send_on_status(peer, peer->next_tx_id++, "NetStream.Play.Start");
    } else if (!strcmp(cmd, "deleteStream")) {
        LLOG(LL_TRACE, "peer %p stream=%s cmd=%s", peer, peer->stream->data, cmd);
        if (peer->rtz_stream) {
            rtz_stream_del(peer->rtz_stream);
            peer->rtz_stream = NULL;
        }
        if ((peer->flag & RTMP_PEER_PUBLISH) && !sbuf_empty(peer->stream)) {
            rtmp_peer_t *p, *tmp;
            list_for_each_entry_safe(p, tmp, &peer->srv->peer_list, link) {
                if ((p->flag & RTMP_PEER_PLAY)
                    && p != peer
                    && !strcmp(peer->stream->data, p->stream->data)) {
                    rtmp_peer_del(p);
                }

            }
        }
        peer->flag &= ~RTMP_PEER_PUBLISH;
        peer->flag &= ~(RTMP_PEER_PLAY | RTMP_PEER_IFRAME_READY);
    } else if (!strcmp(cmd, "FCPublish")) {
        /* ignore */
    } else if (!strcmp(cmd, "FCUnpublish")) {
        /* ignore */
    } else {
        LLOG(LL_WARN, "ignore cmd '%s' tx_id=%u", cmd, tx_id);
    }
}

void event_handler(rtmp_peer_t *peer, rtmp_event_type_t type,
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

// rmtp_spec, 7.2.1.1
void send_connect_result(rtmp_peer_t *peer, unsigned tx_id)
{
    rtmp_response_t *response = rtmp_response_new(peer, "_result", RTMP_SYSTEM_CHANNEL);
    const size_t BUF_SIZE = 4096;
    sbuf_reserve(response->buf, BUF_SIZE);
    const char *pend = response->buf->data + BUF_SIZE;
    char *p = response->buf->data;

    p += amf0_write_string (p, pend - p, "_result");
    p += amf0_write_number(p, pend - p, tx_id);

    p += amf0_write_object_start (p, pend - p);
    p += amf0_write_field_name (p, pend - p, "fmsVer");
    p += amf0_write_string (p, pend - p, "FMS/3,5,3,888");
    p += amf0_write_field_name (p, pend - p, "capabilities");
    p += amf0_write_number (p, pend - p, 31);
    p += amf0_write_object_end (p, pend - p);

    p += amf0_write_object_start (p, pend - p);
    p += amf0_write_field_name (p, pend - p, "level");
    p += amf0_write_string (p, pend - p, "status");
    p += amf0_write_field_name (p, pend - p, "code");
    p += amf0_write_string (p, pend - p, "NetConnection.Connect.Success");
    p += amf0_write_field_name (p, pend - p, "description");
    p += amf0_write_string (p, pend - p, "Connection succeeded.");
    p += amf0_write_field_name (p, pend - p, "objectEncoding");
    p += amf0_write_number (p, pend - p, 3);
    p += amf0_write_object_end (p, pend - p);
    response->buf->size = p - response->buf->data;
    add_cmd_response(peer, response);
}

void send_create_stream_result(rtmp_peer_t *peer, unsigned tx_id)
{
    rtmp_response_t *response = rtmp_response_new(peer, "_result", RTMP_SYSTEM_CHANNEL);
    const size_t BUF_SIZE = 1024;
    sbuf_reserve(response->buf, BUF_SIZE);
    const char *pend = response->buf->data + BUF_SIZE;
    char *p = response->buf->data;

    p += amf0_write_string (p, pend - p, "_result");
    p += amf0_write_number (p, pend - p, tx_id);
    p += amf0_write_null (p, pend - p);
    p += amf0_write_number (p, pend - p, 1);

    response->buf->size = p - response->buf->data;
    add_cmd_response(peer, response);
}

void add_response(rtmp_peer_t *peer, uint32_t timestamp, rtmp_message_type_t type,
                  uint32_t stream_id, rtmp_response_t *response)
{
    //LLOG(LL_TRACE, "%u", timestamp);
    response->timestamp = zl_timestamp();
    rtmp_write_chunk(response->channel, timestamp, type, stream_id,
                     response->buf->data, response->buf->size,
                     rtmp_write_handler, peer->chan);
    rtmp_response_del(response);
}

void add_event_response(rtmp_peer_t *peer, rtmp_response_t *response)
{
    add_response(peer, 0, RTMP_MESSAGE_USER_CONTROL, 0, response);
}

void add_cmd_response(rtmp_peer_t *peer, rtmp_response_t *response)
{
    add_response(peer, 0, RTMP_MESSAGE_AMF0_CMD, 0, response);
}

rtmp_response_t *rtmp_response_new(rtmp_peer_t *peer, const char *method, unsigned channel)
{
    assert(channel < RTMP_MAX_CHUNK_STREAMS);
    rtmp_response_t *req = malloc(sizeof(rtmp_response_t));
    req->method = method;
    req->channel = channel;
    req->tx_id = peer->next_tx_id++;
    req->buf = sbuf_new();
    INIT_LIST_HEAD(&req->link);
    return req;
}

void rtmp_response_del(rtmp_response_t *req)
{
    sbuf_del(req->buf);
    free(req);
}

/*
void update_poll_events(rtmp_peer_t *peer)
{
    if (peer->flag & RTMP_PEER_ERROR) {
        if (peer->eevents) {
            peer->eevents = 0;
            zl_fd_ctl(peer->loop, EPOLL_CTL_DEL, peer->fd, 0, NULL, peer);
        }
        return;
    }

    uint32_t pevents = 0;
    if (!(peer->flag & RTMP_PEER_EOF))
        pevents |= EPOLLIN;
    if (!sbuf_empty(peer->snd_buf))
        pevents |= EPOLLOUT;
    if (pevents != peer->eevents) {
        peer->eevents = pevents;
        if (pevents)
            zl_fd_ctl(peer->loop, EPOLL_CTL_MOD , peer->fd, pevents,
                      peer_fd_event_handler, peer);
        else
            zl_fd_ctl(peer->loop, EPOLL_CTL_DEL, peer->fd, 0, NULL, peer);
    }
}
*/

void send_on_status(rtmp_peer_t *peer, unsigned tx_id, const char *status)
{
    rtmp_response_t *response = rtmp_response_new(peer, "onStatus", RTMP_NOTIFY_CHANNEL);
    const size_t BUF_SIZE = 1024;
    sbuf_reserve(response->buf, BUF_SIZE);
    const char *pend = response->buf->data + BUF_SIZE;
    char *p = response->buf->data;

    p += amf0_write_string (p, pend - p, "onStatus");
    p += amf0_write_number (p, pend - p, tx_id);
    p += amf0_write_null (p, pend - p);

    p += amf0_write_object_start (p, pend - p);
    p += amf0_write_field_name (p, pend - p, "level");
    p += amf0_write_string (p, pend - p, "status");
    p += amf0_write_field_name (p, pend - p, "code");
    p += amf0_write_string (p, pend - p, status);
    p += amf0_write_field_name (p, pend - p, "description");
    p += amf0_write_string (p, pend - p, status);
    p += amf0_write_object_end (p, pend - p);

    response->buf->size = p - response->buf->data;
    add_cmd_response(peer, response);
}

void send_stream_event(rtmp_peer_t *peer, rtmp_event_type_t event)
{
    rtmp_response_t *response = rtmp_response_new(peer, "NetStream.Event", RTMP_NETWORK_CHANNEL);
    const size_t BUF_SIZE = 1024;
    sbuf_reserve(response->buf, BUF_SIZE);
    const char *pend = response->buf->data + BUF_SIZE;
    char *p = response->buf->data;

    p += pack_be16(p, event);
    p += pack_be32(p, 1);

    response->buf->size = p - response->buf->data;
    add_event_response(peer, response);
}

void rtmp_write_handler(const void *data, int size, void *udata)
{
    tcp_chan_t *chan = udata;
    tcp_chan_write(chan, data, size);
}

void rtmp_stream_set_video_codec_h264(rtmp_peer_t *peer, uint32_t timestamp,
                                      const void *data, int size)
{
    rtmp_response_t *response = rtmp_response_new(peer, "AVC.SequenceHeader", RTMP_VIDEO_CHANNEL);
    const size_t BUF_SIZE = 16;
    sbuf_reserve(response->buf, BUF_SIZE + size);
    const char *pend = sbuf_tail(response->buf);
    char *p = response->buf->data;
    *p++ = (FLV_VIDEO_KEY_FRAME << 4) | FLV_VIDEO_CODEC_H264; // FrameType & CodecID
    *p++ = FLV_AVC_SEQUENCE_HEADER;    // AVCPacketType
    p += pack_be24 (p, 0);  // CompositionTime
    memcpy(p, data, size);
    p += size;
    response->buf->size = p - response->buf->data;
    add_response(peer, timestamp, RTMP_MESSAGE_VIDEO, 1, response);
}

void send_notify(rtmp_peer_t *peer, const char *event, const void *data, int size)
{
    rtmp_response_t *response = rtmp_response_new(peer, "Notify", RTMP_NOTIFY_CHANNEL);
    const size_t BUF_SIZE = 16;
    sbuf_reserve(response->buf, BUF_SIZE + strlen(event) + size);
    const char *pend = sbuf_tail(response->buf);
    char *p = response->buf->data;

    p += amf0_write_string (p, pend - p, event);
    memcpy(p, data, size);
    p += size;

    response->buf->size = p - response->buf->data;
    add_response(peer, 0, RTMP_MESSAGE_AMF0_NOTIFY, 1, response);
}

void set_video_codec_h264(rtmp_server_t *srv, const char *stream_name,
                          uint32_t timestamp, const char *data, int size)
{
    rtmp_peer_t *p, *tmp;
    list_for_each_entry_safe(p, tmp, &srv->peer_list, link) {
        if ((p->flag & RTMP_PEER_PLAY) && !strcmp(p->stream->data, stream_name)) {
            rtmp_stream_set_video_codec_h264(p, timestamp, data, size);
        }
    }
}

void rtmp_stream_push_video(rtmp_peer_t *peer, uint32_t timestamp,
                            int key_frame, const void *data, int size)
{
    if (key_frame)
        peer->flag |= RTMP_PEER_IFRAME_READY;
    if (!(peer->flag & RTMP_PEER_IFRAME_READY))
        return;

    rtmp_response_t *response = rtmp_response_new(peer, "AVC.VideoData", RTMP_VIDEO_CHANNEL);
    const size_t BUF_SIZE = 16;
    sbuf_reserve(response->buf, BUF_SIZE + size);
    const char *pend = sbuf_tail(response->buf);
    char *p = response->buf->data;
    *p++ = ((key_frame ? FLV_VIDEO_KEY_FRAME : FLV_VIDEO_INTER_FRAME) << 4)
        | FLV_VIDEO_CODEC_H264; // FrameType & CodecID
    *p++ = FLV_AVC_NALU;    // AVCPacketType
    p += pack_be24(p, 0);  // CompositionTime
    p += pack_be32(p, size); // nalu size
    memcpy(p, data, size);
    p += size;
    response->buf->size = p - response->buf->data;
    add_response(peer, timestamp, RTMP_MESSAGE_VIDEO, 1, response);
}

void rtmp_stream_push_audio(rtmp_peer_t *peer, uint32_t timestamp,
                            const void *data, int size)
{
    if (!(peer->flag & RTMP_PEER_IFRAME_READY))
        return;
    rtmp_response_t *response = rtmp_response_new(peer, "PCMA.AudioData", RTMP_AUDIO_CHANNEL);
    const size_t BUF_SIZE = 16;
    sbuf_reserve(response->buf, BUF_SIZE + size);
    const char *pend = sbuf_tail(response->buf);
    char *p = response->buf->data;
    /* SoundFormat  UB[4]   PCMA
       SoundRate    UB[2]   0(ignore)
       SoundSize    UB[1]   0:8-bit
       SoundType    UB[1]   0:Mono */
    *p++ = (FLV_AUDIO_CODEC_PCMA << 4);
    memcpy(p, data, size);
    p += size;
    response->buf->size = p - response->buf->data;
    add_response(peer, timestamp, RTMP_MESSAGE_AUDIO, 1, response);
}

void rtmp_get_player(rtmp_server_t *srv, const char *stream_name, int *player_count)
{
    rtmp_peer_t *p;
    *player_count = 0;
    list_for_each_entry(p, &srv->peer_list, link) {
        if ((p->flag & RTMP_PEER_PLAY) && !strcmp(p->stream->data, stream_name))
            ++*player_count;
    }
}

void push_video(rtmp_server_t *srv, const char *stream_name,
                uint32_t timestamp, int key_frame, const void *data, int size)
{
    rtmp_peer_t *p, *tmp;
    list_for_each_entry_safe(p, tmp, &srv->peer_list, link) {
        if ((p->flag & RTMP_PEER_PLAY) && !strcmp(p->stream->data, stream_name)) {
            rtmp_stream_push_video(p, timestamp, key_frame, data, size);
        }
    }
}
void push_audio(rtmp_server_t *srv, const char *stream_name,
                uint32_t timestamp, const void *data, int size)
{
    rtmp_peer_t *p, *tmp;
    list_for_each_entry_safe(p, tmp, &srv->peer_list, link) {
        if ((p->flag & RTMP_PEER_PLAY) && !strcmp(p->stream->data, stream_name)) {
            rtmp_stream_push_audio(p, timestamp, data, size);
        }
    }
}
