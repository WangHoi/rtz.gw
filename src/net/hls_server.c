#include "hls_server.h"
#include "event_loop.h"
#include "tcp_chan.h"
#include "list.h"
#include "http_types.h"
#include "sbuf.h"
#include "log.h"
#include "rtmp_client.h"
#include "media/fmp4_mux.h"
#include "media/codec_types.h"
#include "media/flac_util.h"
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
#include <sys/uio.h>
#include <cJSON.h>
#include <time.h>
#include <math.h>

enum http_parse_state {
    HTTP_PARSE_HEADER,
    HTTP_PARSE_BODY,
};

enum http_peer_flag {
    HTTP_PEER_CLOSE_ASAP = 1,
    HTTP_PEER_ERROR = 2,
};

enum {
    /** Time before EOF hls_stream_t */
    HLS_NO_VIDEO_EOF_TIMEOUT_MSECS = 10000,
    /** Time before release hls_stream_t */
    HLS_NO_VIDEO_CLEANUP_TIMEOUT_MSECS = 15000,
    HLS_NO_OUTPUT_CLEANUP_TIMEOUT_MSECS = 5000,
    HLS_CRON_TIMEOUT_MSECS = 1000,
    DEFAULT_VOD_DURATION = 0,
    EVICT_FRAG_THREHOLD = 5,
    PAUSE_RTMP_FRAG_THREHOLD = 12,
    RESUME_RTMP_FRAG_THREHOLD = 8,
};

typedef struct http_peer_t http_peer_t;
typedef struct hls_stream_t hls_stream_t;
typedef struct hls_fragment_t hls_fragment_t;

struct hls_server_t {
    zl_loop_t *loop;
    tcp_srv_t *tcp_srv;
    int timer;

    struct list_head peer_list;     /* http_peer_t list */
    struct list_head stream_list;   /* hls_stream_t list */
};

struct http_peer_t {
    struct list_head link;  // link to hls_server_t.peer_list

    hls_server_t *srv;
    tcp_chan_t *chan;

    enum http_parse_state parse_state;
    sbuf_t *parse_buf;
    http_request_t *parse_request; // partial request waiting body

    int flag;
    struct list_head req_list;

    sbuf_t *url_path;
};

/** hls_stream_t connect publisher and subscribers together
 *
 * In Edge mode, hls_stream_t created by first http_peer_t fetching m3u8,
 *      and hls_stream_t own the rtmp_client.
 */
struct hls_stream_t {
    /** link to hls_server_t.stream_list */
    struct list_head link;
    hls_server_t *srv;

    sbuf_t *tc_url;
    sbuf_t *app;
    /** Such as 'realTime_xxx_0_0' */
    sbuf_t *stream_name;
    rtmp_client_t *rtmp_client;

    sbuf_t *m3u8_buf;
    sbuf_t *init_frag_buf;
    unsigned long frag_seq;
    unsigned long media_seq;
    struct list_head media_frag_list;
    fmp4_mux_t *mux_ctx;
    int mux_started;
    sbuf_t *codec_config_cache;
    video_codec_type_t vcodec_type;
    int width;
    int height;
    audio_codec_type_t acodec_type;
    int vcodec_changed;
    long pdt_changed;
    int eof;
    int paused;
    long long last_in_time;
    long long last_out_time;
};

struct hls_fragment_t {
    struct list_head link;
    int fetched;
    int vcodec_changed;
    unsigned long seq;
    double duration;
    sbuf_t *path;
    sbuf_t *m3u8_buf;
    sbuf_t *data_buf;
};

extern const char *RTZ_PUBLIC_IP;
extern int RTZ_PUBLIC_SIGNAL_PORT;

extern void make_origin_url(sbuf_t *origin_url, const char *tc_url, const char *stream_name);

static void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata);
static void http_request_handler(http_peer_t *peer, http_request_t *req);
static void peer_data_handler(tcp_chan_t *chan, void *udata);
static void peer_error_handler(tcp_chan_t *chan, int status, void *udata);

static http_peer_t *http_peer_new(hls_server_t *srv, tcp_chan_t *chan);
static void http_peer_del(http_peer_t *peer);
static void send_final_reply(http_peer_t *peer, http_status_t status);
static void send_reply_data(http_peer_t *peer, const void *data, int size);
static void parse_m3u8_path(hls_stream_t *h, const char *url);
static void parse_fragment_path(sbuf_t *stream_name, sbuf_t *frag_name, const char *url);
static hls_stream_t *find_stream(hls_server_t *srv, const char *stream_name);
static hls_fragment_t *find_fragment(struct list_head *list, const char *name);
static hls_stream_t *hls_stream_new(hls_server_t *srv);
static void hls_stream_del(hls_stream_t *stream);
static void hls_server_cron(zl_loop_t *loop, int timerid, void *udata);

static void rtmp_audio_handler(int64_t timestamp, uint16_t sframe_time,
    int key_frame, const void *data, int size, void *udata);
static void rtmp_video_handler(int64_t timestamp, uint16_t sframe_time,
    int key_frame, const void *data, int size, void *udata);
static void rtmp_video_codec_handler(const void *data, int size, void *udata);
static void rtmp_metadata_handler(int vcodec, int acodec, double videotime, void *udata);
static int update_codec_info(hls_stream_t *stream, const char *data, int size);

static void update_stream_m3u8_buf(hls_stream_t *stream);
static void update_frag_m3u8_buf(hls_stream_t *stream, hls_fragment_t *frag);
static void check_evict_fragment(hls_stream_t *h);
static void check_stream_congestion(hls_stream_t *h);
static hls_fragment_t *hls_fragment_new(hls_stream_t *stream);
static void hls_fragment_del(hls_fragment_t *frag);

hls_server_t *hls_server_new(zl_loop_t *loop)
{
    hls_server_t *srv;
    int ret;
    srv = malloc(sizeof(hls_server_t));
    memset(srv, 0, sizeof(hls_server_t));
    srv->loop = loop;
    srv->tcp_srv = tcp_srv_new(loop);
    INIT_LIST_HEAD(&srv->peer_list);
    INIT_LIST_HEAD(&srv->stream_list);
    srv->timer = zl_timer_start(loop, HLS_CRON_TIMEOUT_MSECS, HLS_CRON_TIMEOUT_MSECS, hls_server_cron, srv);
    //LLOG(LL_INFO, "shard=%d ice_srv=%p", rtz_shard_get_index_ct(), srv->ice_srv);
    return srv;
}

void hls_server_del(hls_server_t *srv)
{
    tcp_srv_del(srv->tcp_srv);
    zl_timer_stop(srv->loop, srv->timer);
    free(srv);
}

int hls_server_bind(hls_server_t *srv, unsigned short port)
{
    return tcp_srv_bind(srv->tcp_srv, NULL, port);
}

int hls_server_start(hls_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, accept_handler, srv);
    return tcp_srv_listen(srv->tcp_srv);
}

void hls_server_stop(hls_server_t *srv)
{
    tcp_srv_set_cb(srv->tcp_srv, NULL, NULL);
    http_peer_t *p, *ptmp;
    list_for_each_entry_safe(p, ptmp, &srv->peer_list, link) {
        http_peer_del(p);
    }
    hls_stream_t *s, *stmp;
    list_for_each_entry_safe(s, stmp, &srv->stream_list, link) {
        hls_stream_del(s);
    }
}

void accept_handler(tcp_srv_t *tcp_srv, tcp_chan_t *chan, void *udata)
{
    hls_server_t *srv = udata;
    http_peer_t *peer = http_peer_new(srv, chan);
    if (!peer) {
        LLOG(LL_ERROR, "http_peer_new error.");
        return;
    }
    tcp_chan_set_cb(peer->chan, peer_data_handler, NULL, peer_error_handler, peer);
}

void peer_data_handler(tcp_chan_t *chan, void *udata)
{
    http_peer_t *peer = udata;
    while (!tcp_chan_read_buf_empty(chan)) {
        if (peer->parse_state == HTTP_PARSE_HEADER) {
            char c = tcp_chan_readc(chan);
            sbuf_appendc(peer->parse_buf, c);
            if (sbuf_ends_with(peer->parse_buf, "\r\n\r\n")) {
                http_request_t *req = http_parse_request(peer, peer->parse_buf->data,
                    sbuf_tail(peer->parse_buf));
                sbuf_clear(peer->parse_buf);
                if (req) {
                    peer->parse_request = req;
                    if (req->body_len) {
                        peer->parse_state = HTTP_PARSE_BODY;
                    } else {
                        http_request_handler(peer, req);
                        peer->parse_request = NULL;
                    }
                } else {
                    send_final_reply(peer, HTTP_STATUS_BAD_REQUEST);
                }
            }
        } else if (peer->parse_state == HTTP_PARSE_BODY) {
            if (peer->parse_request->body_len <= tcp_chan_get_read_buf_size(chan)) {
                tcp_chan_read(chan, peer->parse_request->body,
                    peer->parse_request->body_len);
                http_request_handler(peer, peer->parse_request);
                peer->parse_request = NULL;
                peer->parse_state = HTTP_PARSE_HEADER;
            } else {
                break;
            }
        } else {
            assert(0);
        }
    }
    if ((peer->flag & HTTP_PEER_ERROR)
        || (peer->flag & HTTP_PEER_CLOSE_ASAP)) {
        http_peer_del(peer);
    }
}

void peer_error_handler(tcp_chan_t *chan, int status, void *udata)
{
    http_peer_t *peer = udata;
    LLOG(LL_ERROR, "peer %p event %d.", peer, status);
    http_peer_del(peer);
}

http_peer_t *http_peer_new(hls_server_t *srv, tcp_chan_t *chan)
{
    http_peer_t *peer = malloc(sizeof(http_peer_t));
    if (peer == NULL)
        return NULL;
    memset(peer, 0, sizeof(http_peer_t));
    peer->srv = srv;
    peer->chan = chan;
    peer->parse_state = HTTP_PARSE_HEADER;
    peer->parse_buf = sbuf_new1(MAX_HTTP_HEADER_SIZE);
    peer->url_path = sbuf_new();
    INIT_LIST_HEAD(&peer->req_list);
    list_add(&peer->link, &srv->peer_list);
    return peer;
}

void http_peer_del(http_peer_t * peer)
{
    //LLOG(LL_TRACE, "delete http_peer %p", peer);
    if (peer->parse_request)
        http_request_del(peer->parse_request);
    tcp_chan_close(peer->chan, 0);
    sbuf_del(peer->parse_buf);
    sbuf_del(peer->url_path);
    list_del(&peer->link);
    free(peer);
}

void send_final_reply(http_peer_t *peer, http_status_t status)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 %d %s\r\n"
        "Connection:Keepalive\r\n"
        "Access-Control-Allow-Origin:*\r\n"
        "Access-Control-Allow-Headers:range\r\n"
        "Access-Control-Allow-Methods:GET\r\n"
        "\r\n",
        status, http_strstatus(status));
    if (n > 0) {
        tcp_chan_write(peer->chan, s, n);
        free(s);
    }
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}

void send_reply_data(http_peer_t *peer, const void *data, int size)
{
    if (peer->flag & HTTP_PEER_ERROR)
        return;
    char *s;
    int n = asprintf(&s, "HTTP/1.1 200 OK\r\n"
        "Connection:Keepalive\r\n"
        "Content-Length:%d\r\n"
        "Access-Control-Allow-Origin:*\r\n"
        "Access-Control-Allow-Headers:range\r\n"
        "Access-Control-Allow-Methods:GET\r\n"
        "\r\n",
        size);
    tcp_chan_write(peer->chan, s, n);
    free(s);
    tcp_chan_write(peer->chan, data, size);
    peer->flag |= HTTP_PEER_CLOSE_ASAP;
}
void http_request_handler(http_peer_t *peer, http_request_t *req)
{
    if (peer->flag & HTTP_PEER_ERROR) {
        http_request_del(req);
        return;
    }

    list_add_tail(&req->link, &peer->req_list);
    if (peer->req_list.next != &req->link)
        return;

    if (req->method != HTTP_METHOD_GET && req->method != HTTP_METHOD_OPTIONS) {
        send_final_reply(peer, HTTP_STATUS_INTERNAL_SERVER_ERROR);
        list_del(&req->link);
        http_request_del(req);
        return;
    }

    if (req->method == HTTP_METHOD_OPTIONS) {
        send_final_reply(peer, HTTP_STATUS_OK);
        return;
    }

    sbuf_strcpy(peer->url_path, req->path);
    sbuf_t *stream_name = sbuf_new();
    sbuf_t *frag_name = sbuf_new();
    parse_fragment_path(stream_name, frag_name, req->path);
    //LLOG(LL_TRACE, "path='%s' stream_name='%s', frag_name='%s'",
    //    req->path, stream_name->data, frag_name->data);
    hls_stream_t *stream = find_stream(peer->srv, stream_name->data);
    if (sbuf_ends_withi(peer->url_path, ".m3u8")) {
        if (!stream) {
            LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);

            stream = hls_stream_new(peer->srv);
            parse_m3u8_path(stream, req->path);

            rtmp_client_t *client = rtmp_client_new(peer->srv->loop);
            sbuf_t *origin_url = sbuf_new1(1024);
            make_origin_url(origin_url, stream->tc_url->data, stream->stream_name->data);
            rtmp_client_set_uri(client, origin_url->data);
            rtmp_client_tcp_connect(client, NULL);
            rtmp_client_set_userdata(client, stream);
            rtmp_client_set_audio_packet_cb(client, rtmp_audio_handler);
            rtmp_client_set_video_packet_cb(client, rtmp_video_handler);
            rtmp_client_set_video_codec_cb(client, rtmp_video_codec_handler);
            rtmp_client_set_metadata_cb(client, rtmp_metadata_handler);
            stream->rtmp_client = client;
            LLOG(LL_TRACE, "add new stream %s origin_url='%s'", stream->stream_name->data, origin_url->data);
            sbuf_del(origin_url);
        }
        stream->last_out_time = zl_time();
        send_reply_data(peer, stream->m3u8_buf->data, stream->m3u8_buf->size);
    } else if (sbuf_ends_withi(peer->url_path, ".mp4")) {
        //LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);
        if (stream) {
            stream->last_out_time = zl_time();
            send_reply_data(peer, stream->init_frag_buf->data, stream->init_frag_buf->size);
        } else {
            send_final_reply(peer, HTTP_STATUS_NOT_FOUND);
        }
    } else if (sbuf_ends_withi(peer->url_path, ".m4s")) {
        //LLOG(LL_TRACE, "handle: %s %s", http_strmethod(req->method), req->path);
        if (stream) {
            hls_fragment_t *frag = find_fragment(&stream->media_frag_list, frag_name->data);
            if (frag) {
                frag->fetched = 1;
                stream->last_out_time = zl_time();
                send_reply_data(peer, frag->data_buf->data, frag->data_buf->size);
                /* check evict fragment */
                check_evict_fragment(stream);
                /* may resume */
                check_stream_congestion(stream);
            } else {
                send_final_reply(peer, HTTP_STATUS_NOT_FOUND);
            }
        } else {
            send_final_reply(peer, HTTP_STATUS_NOT_FOUND);
        }
    } else {
        send_final_reply(peer, HTTP_STATUS_NOT_FOUND);
    }
    sbuf_del(stream_name);
    sbuf_del(frag_name);
    list_del(&req->link);
    http_request_del(req);
}

/** Parse url, fill peer's fields: app, tc_url, stream_name */
void parse_m3u8_path(hls_stream_t *h, const char *url)
{
    const char *p = url;
    if (p) {
        const char *q1 = strchr(p + 1, '?');
        const char *q2 = strchr(p + 1, '/');
        const char *q;
        if (!q1)
            q = q2;
        else if (!q2)
            q = q1;
        else
            q = (q1 < q2) ? q1 : q2;
        if (q)
            sbuf_strncpy(h->app, p + 1, q - (p + 1));
        else
            sbuf_strcpy(h->app, p + 1);
    } else {
        sbuf_strcpy(h->app, "live");
    }
    p = strrchr(url, '/');
    sbuf_printf(h->tc_url, "rtmp://%s:%d", RTZ_PUBLIC_IP, RTZ_PUBLIC_SIGNAL_PORT);
    if (p) {
        sbuf_strcpy(h->stream_name, p + 1);
        /* Strip suffix */
        if (sbuf_ends_withi(h->stream_name, ".m3u8")) {
            h->stream_name->data[h->stream_name->size - 5] = 0;
            h->stream_name->size -= 5;
        }
        sbuf_append2(h->tc_url, url, p - url);
    } else {
        sbuf_append1(h->tc_url, url);
    }
    LLOG(LL_TRACE, "parse_m3u8_path('%s'): app='%s' tcUrl='%s' streamName='%s'",
         url, h->app->data, h->tc_url->data, h->stream_name->data);
}

hls_stream_t *hls_stream_new(hls_server_t *srv)
{
    hls_stream_t *stream = malloc(sizeof(hls_stream_t));
    memset(stream, 0, sizeof(hls_stream_t));
    stream->srv = srv;
    stream->tc_url = sbuf_new();
    stream->app = sbuf_new();
    stream->stream_name = sbuf_new();
    stream->m3u8_buf = sbuf_new();
    stream->init_frag_buf = sbuf_new();
    INIT_LIST_HEAD(&stream->media_frag_list);
    list_add(&stream->link, &srv->stream_list);
    stream->mux_ctx = fmp4_mux_new();
    stream->codec_config_cache = sbuf_new();
    stream->vcodec_type = INVALID_VIDEO_CODEC;
    stream->acodec_type = INVALID_AUDIO_CODEC;
    stream->width = 1280;
    stream->height = 720;
    stream->last_in_time = stream->last_out_time = zl_time();
    update_stream_m3u8_buf(stream);
    return stream;
}

void hls_stream_del(hls_stream_t *stream)
{
    LLOG(LL_INFO, "hls_stream_del %p(%s)", stream, stream->stream_name->data);
    if (stream->rtmp_client) {
        rtmp_client_del(stream->rtmp_client);
        stream->rtmp_client = NULL;
    }
    list_del(&stream->link);
    sbuf_del(stream->tc_url);
    sbuf_del(stream->app);
    sbuf_del(stream->stream_name);
    sbuf_del(stream->m3u8_buf);
    sbuf_del(stream->init_frag_buf);
    fmp4_mux_del(stream->mux_ctx);
    sbuf_del(stream->codec_config_cache);
    hls_fragment_t *f, *ftmp;
    list_for_each_entry_safe(f, ftmp, &stream->media_frag_list, link) {
        hls_fragment_del(f);
    }
    INIT_LIST_HEAD(&stream->media_frag_list);
    free(stream);
}

/* Parse fragment path
 * '/live?token=XX/cloudRecord_xx.m3u8' -> 'cloudRecord_xx', ''
 * '/live/cloudRecord_xx.mp4' -> 'cloudRecord_xx', ''
 * '/live/cloudRecord_xx/0.m4s' -> 'cloudRecord_xx', '0.m4s'
 */
void parse_fragment_path(sbuf_t *stream_name, sbuf_t *frag_name, const char *path)
{
    const char *r = strrchr(path, '.');
    if (!r) {
        sbuf_clear(stream_name);
        sbuf_clear(frag_name);
        return;
    }
    if (!strcmp(r, ".m3u8") || !strcmp(r, ".mp4")) {
        const char *p = strrchr(path, '/');
        if (!p) {
            sbuf_strncpy(stream_name, path, r - path);
        } else {
            sbuf_strncpy(stream_name, p + 1, r - (p + 1));
        }
        sbuf_clear(frag_name);
    } else if (!strcmp(r, ".m4s")) {
        const char *p = strrchr(path, '/');
        if (!p) {
            LLOG(LL_ERROR, "invalid url path '%s'", path);
            sbuf_strcpy(frag_name, path);
            sbuf_clear(stream_name);
        } else {
            sbuf_strcpy(frag_name, p + 1);
            const char *q = memrchr(path, '/', p - path);
            if (!q) {
                sbuf_strncpy(stream_name, path, p - path);
            } else {
                sbuf_strncpy(stream_name, q + 1, p - (q + 1));
            }
        }
    } else {
        sbuf_clear(stream_name);
        sbuf_clear(frag_name);
    }
}

hls_stream_t *find_stream(hls_server_t *srv, const char *stream_name)
{
    hls_stream_t *s;
    list_for_each_entry(s, &srv->stream_list, link) {
        if (!strcmp(s->stream_name->data, stream_name))
            return s;
    }
    return NULL;
}

hls_fragment_t *find_fragment(struct list_head *list, const char *name)
{
    hls_fragment_t *f;
    list_for_each_entry(f, list, link) {
        if (!strcmp(f->path->data, name))
            return f;
    }
    return NULL;
}

void rtmp_audio_handler(int64_t timestamp, uint16_t sframe_time,
    int key_frame, const void *data, int size, void *udata)
{
    hls_stream_t *h = udata;
    if (!h->mux_started)
        return;
    if (h->acodec_type != AUDIO_CODEC_PCMA)
        return;

    int64_t pts = timestamp * 8;
    int32_t duration = size;
    int samples = duration;
    sbuf_t *flac_frame = flac_encode_pcma(data, samples);
    fmp4_mux_media_sample(h->mux_ctx, 0, pts, duration,
        key_frame, flac_frame->data, flac_frame->size);
    sbuf_del(flac_frame);
}

void rtmp_video_handler(int64_t timestamp, uint16_t sframe_time,
    int key_frame, const void *data, int size, void *udata)
{
    hls_stream_t *h = udata;
    if (h->eof)
        return;

    if (key_frame) {
        /* avoid too short fragment */
        if (h->mux_started && fmp4_mux_duration(h->mux_ctx, timestamp * 90) >= 0.9) {
            hls_fragment_t *frag = hls_fragment_new(h);
            fmp4_mux_media_end(h->mux_ctx,
                frag->seq, timestamp * 90, frag->data_buf, &frag->duration);

            /* generate fragment m3u8 */
            update_frag_m3u8_buf(h, frag);

            /* may pause source */
            check_stream_congestion(h);

            /* update stream m3u8 */
            update_stream_m3u8_buf(h);

            fmp4_mux_media_start(h->mux_ctx);
        }
        h->mux_started = 1;
    }
    if (!h->mux_started)
        return;
    h->last_in_time = zl_time();
    fmp4_mux_media_sample(h->mux_ctx, 1, timestamp * 90,
        sframe_time * 90, key_frame, data, size);
}

void rtmp_video_codec_handler(const void *data, int size, void *udata)
{
    hls_stream_t *h = udata;
    int changed = update_codec_info(h, data, size);
    if (!changed)
        return;

    //LLOG(LL_TRACE, "vcodec handler");

    if (h->acodec_type == AUDIO_CODEC_PCMA) {
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
        fmp4_mux_init_seg(h->init_frag_buf, DEFAULT_VOD_DURATION,
            h->width, h->height, data, size,
            (h->acodec_type == AUDIO_CODEC_PCMA), dfla, sizeof(dfla));
    } else {
        fmp4_mux_init_seg(h->init_frag_buf, DEFAULT_VOD_DURATION,
            h->width, h->height, data, size,
            0, NULL, 0);
    }
    h->vcodec_changed = 1;
}

void rtmp_metadata_handler(int vcodec, int acodec, double videotime, void *udata)
{
    acodec = INVALID_AUDIO_CODEC;
    hls_stream_t *h = udata;
    h->vcodec_type = vcodec;
    h->acodec_type = acodec;
    h->pdt_changed = (long)videotime;
}

int update_codec_info(hls_stream_t *stream, const char *data, int size)
{
    if (stream->codec_config_cache->size != size
        || memcmp(data, stream->codec_config_cache->data, size)) {

        sbuf_strncpy(stream->codec_config_cache, data, size);
        return 1;
    }
    return 0;
}

void update_stream_m3u8_buf(hls_stream_t *h)
{
    sbuf_clear(h->m3u8_buf);
    sbuf_append1(h->m3u8_buf, "#EXTM3U\n"
        "#EXT-X-VERSION:3\n"
        "#EXT-X-TARGETDURATION:2\n");
    sbuf_appendf(h->m3u8_buf,
        "#EXT-X-MEDIA-SEQUENCE:%ld\n", h->media_seq);
    hls_fragment_t *f;
    list_for_each_entry(f, &h->media_frag_list, link) {
        if (&f->link == h->media_frag_list.next || f->vcodec_changed) {
            sbuf_appendf(h->m3u8_buf, "#EXT-X-MAP:URI=%s.mp4\n",
                h->stream_name->data);
        }
        sbuf_append(h->m3u8_buf, f->m3u8_buf);
    }
    if (h->eof)
        sbuf_append1(h->m3u8_buf, "#EXT-X-ENDLIST\n");
}

void check_evict_fragment(hls_stream_t *h)
{
    if (list_empty(&h->media_frag_list))
        return;
    if (h->eof)
        return;
    hls_fragment_t *first_frag = list_entry(h->media_frag_list.next, hls_fragment_t, link);
    if (!first_frag->fetched)
        return;
    hls_fragment_t *last_frag = list_entry(h->media_frag_list.prev, hls_fragment_t, link);
    if (last_frag->seq - first_frag->seq > EVICT_FRAG_THREHOLD) {
        unsigned long n = last_frag->seq - first_frag->seq - EVICT_FRAG_THREHOLD;
        hls_fragment_t *f = first_frag;
        while (n > 0 && f->fetched) {
            hls_fragment_t *next_f = list_entry(f->link.next, hls_fragment_t, link);
            //LLOG(LL_TRACE, "evict frag %s/%s", h->stream_name->data, f->path->data);
            hls_fragment_del(f);
            f = next_f;
            --n;
            ++h->media_seq;
        }
    }
}

void check_stream_congestion(hls_stream_t *h)
{
    if (h->eof)
        return;
    unsigned long nfrags = 0;
    if (!list_empty(&h->media_frag_list)) {
        hls_fragment_t *first_frag = list_entry(h->media_frag_list.next, hls_fragment_t, link);
        hls_fragment_t *last_frag = list_entry(h->media_frag_list.prev, hls_fragment_t, link);
        nfrags = last_frag->seq - first_frag->seq + 1;
    }

    if (h->paused) {
        if (nfrags <= RESUME_RTMP_FRAG_THREHOLD) {
            LLOG(LL_TRACE, "unblock %s", h->stream_name->data);
            rtmp_client_leave_blocking(h->rtmp_client);
            h->paused = 0;
        }
    } else {
        if (nfrags > PAUSE_RTMP_FRAG_THREHOLD) {
            LLOG(LL_TRACE, "block %s", h->stream_name->data);
            rtmp_client_enter_blocking(h->rtmp_client);
            h->paused = 1;
        }
    }
}

void check_resume_stream(hls_stream_t *h)
{
    if (!h->paused)
        return;
    if (h->eof)
        return;
    int need_resume = 0;
    if (list_empty(&h->media_frag_list)) {
        need_resume = 1;
    } else {
        hls_fragment_t *first_frag = list_entry(h->media_frag_list.next, hls_fragment_t, link);
        hls_fragment_t *last_frag = list_entry(h->media_frag_list.prev, hls_fragment_t, link);
        if (last_frag->seq - first_frag->seq > RESUME_RTMP_FRAG_THREHOLD) {
            need_resume = 1;
        }
    }
    if (need_resume) {
        rtmp_client_enter_blocking(h->rtmp_client);
        h->paused = 0;
    }
}
hls_fragment_t *hls_fragment_new(hls_stream_t *h)
{
    hls_fragment_t *frag = malloc(sizeof(hls_fragment_t));
    memset(frag, 0, sizeof(hls_fragment_t));
    list_add_tail(&frag->link, &h->media_frag_list);
    frag->seq = h->frag_seq;
    frag->path = sbuf_newf("%lu.m4s", h->frag_seq);
    frag->m3u8_buf = sbuf_new();
    frag->data_buf = sbuf_new();
    ++h->frag_seq;
    return frag;
}

void hls_fragment_del(hls_fragment_t *f)
{
    sbuf_del(f->path);
    sbuf_del(f->m3u8_buf);
    sbuf_del(f->data_buf);
    list_del(&f->link);
    free(f);
}

void update_frag_m3u8_buf(hls_stream_t *h, hls_fragment_t *frag)
{
    sbuf_clear(frag->m3u8_buf);
    if (h->vcodec_changed) {
        h->vcodec_changed = 0;
        frag->vcodec_changed = 1;
    }
    if (h->pdt_changed) {
        time_t time = (time_t)(h->pdt_changed / 1000);
        long msecs = h->pdt_changed % 1000;
        struct tm tm;
        char buf[256];
        localtime_r(&time, &tm);
        int n = strftime(buf, sizeof(buf), "%FT%T", &tm);
        n += snprintf(buf + n, sizeof(buf) - n, ".%03ld", msecs);
        n += strftime(buf + n, sizeof(buf) - n, "%z", &tm);
        sbuf_appendf(frag->m3u8_buf, "#EXT-X-PROGRAM-DATE-TIME:%s\n", buf);
        h->pdt_changed = 0;
    }
    sbuf_appendf(frag->m3u8_buf, "#EXTINF:%.3lf,\n%s/%s\n",
        frag->duration, h->stream_name->data, frag->path->data);
}

void hls_server_cron(zl_loop_t *loop, int timerid, void *udata)
{
    hls_server_t *srv = udata;
    hls_stream_t *stream, *tmp;
    long long now = zl_time();
    list_for_each_entry_safe(stream, tmp, &srv->stream_list, link) {
        long long expire_timeout;

        /* No player timeout */
        expire_timeout = HLS_NO_OUTPUT_CLEANUP_TIMEOUT_MSECS + lrand48() % 1000;
        if (now > stream->last_out_time + expire_timeout) {
            LLOG(LL_ERROR, "hls_stream_t %p(%s) output timeout %lld ms", stream,
                stream->stream_name->data, now - stream->last_out_time);
            hls_stream_del(stream);
            continue;
        }

        /* No source force EOF timeout */
        expire_timeout = HLS_NO_VIDEO_EOF_TIMEOUT_MSECS + lrand48() % 1000;
        if (!stream->paused && now > stream->last_in_time + expire_timeout && !stream->eof) {
            LLOG(LL_ERROR, "hls_stream_t %p(%s) EOF after %lld ms", stream,
                stream->stream_name->data, now - stream->last_in_time);
            stream->eof = 1;
            update_stream_m3u8_buf(stream);
            continue;
        }

        /* No source timeout */
        expire_timeout = HLS_NO_VIDEO_CLEANUP_TIMEOUT_MSECS + lrand48() % 1000;
        if (!stream->paused && now > stream->last_in_time + expire_timeout) {
            LLOG(LL_ERROR, "hls_stream_t %p(%s) input timeout %lld ms", stream,
                stream->stream_name->data, now - stream->last_in_time);
            hls_stream_del(stream);
            continue;
        }

    }
}
