#include "sdp.h"
#include "list.h"
#include "sbuf.h"
#include "log.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <assert.h>

struct sdp_t {
    int valid;
    int ntracks;
    struct list_head track_list;
};

struct sdp_track_t {
    int index;
    sbuf_t *type;
    sbuf_t *control;
    int payload;
    sbuf_t *codec;
    sbuf_t *codec_param;
    int sample_rate;
    sbuf_t *fmtp;
    struct list_head link;
};

static sdp_track_t *sdp_track_new();
static void sdp_track_del(sdp_track_t *t);
static sdp_track_t *find_track(sdp_t *sdp, const char *type);

sdp_t *sdp_new()
{
    sdp_t *sdp = malloc(sizeof(sdp_t));
    sdp->valid = 0;
    sdp->ntracks = 0;
    INIT_LIST_HEAD(&sdp->track_list);
    return sdp;
}

void sdp_del(sdp_t *sdp)
{
    sdp_track_t *track, *tmp;
    list_for_each_entry_safe(track, tmp, &sdp->track_list, link) {
        sdp_track_del(track);
    }
    free(sdp);
}

int sdp_valid(sdp_t *sdp)
{
    return sdp->valid;
}

int sdp_parse(sdp_t *sdp, const char *data)
{
    // cleanup
    sdp_track_t *track, *tmp;
    sdp->valid = 0;
    list_for_each_entry_safe(track, tmp, &sdp->track_list, link) {
        sdp_track_del(track);
    }

    // parse
    const char *p;
    int version = -1;
    int n;
    p = strstr(data, "v=");
    if (!p) {
        LLOG(LL_ERROR, "'v=' not found.");
        goto out;
    }
    sscanf (p + 2, " %d", &version);
    if (version != 0) {
        LLOG(LL_ERROR, "unknown SDP version=%d.", version);
        goto out;
    }
    while ((p = strstr(p + 2, "m=")) != NULL) {
        sdp_track_t *track = sdp_track_new();
        char *s = NULL, *q = NULL, *r = NULL;
        track->index = sdp->ntracks++;
        n = sscanf (p, "m=%ms\r\n", &s);
        if (n != 1) {
            sdp_track_del(track);
            continue;
        }
        sbuf_strcpy(track->type, s);
        free(s);
        s = strstr(p, "a=control:");
        if (!s) {
            sbuf_makeroom(track->control, 32);
            track->control->size = sprintf(track->control->data, "trackID=%d", track->index + 1);
            assert(track->control->size < track->control->capacity);
        } else {
            n = sscanf (s, "a=control:%ms\r\n", &q);
            if (n == 1) {
                sbuf_strcpy(track->control, q);
                free(q);
            }
            if (strstr(track->control->data, "rtsp://") == track->control->data) { // strip rtsp://x.x.x.x:xx/
                s = strrchr(track->control->data, '/');
                if (s)
                    sbuf_remove_head(track->control, s - track->control->data + 1);
            }
        }
        s = strstr(p, "a=rtpmap:");
        if (s) {
            n = sscanf (s, "a=rtpmap:%d %m[^/]/%d/%ms\r\n",
                        &track->payload, &q, &track->sample_rate, &r);
            if (n >= 2) {
                sbuf_strcpy(track->codec, q);
                free(q);
            }
            if (n == 4) {
                sbuf_strcpy(track->codec_param, r);
                free(r);
            }
        }
        s = strstr(p, "a=fmtp:");
        if (s) {
            n = sscanf (s, "a=fmtp: %*d %m[^\r]", &q);
            if (n == 1) {
                sbuf_strcpy(track->fmtp, q);
                free(q);
            }
        }
        list_add_tail(&track->link, &sdp->track_list);
        ++sdp->ntracks;
    }
    sdp->valid = 1;

out:
    return sdp->valid;
}

sdp_track_t *sdp_track_new()
{
    sdp_track_t *t = malloc(sizeof(sdp_track_t));
    t->index = -1;
    t->type = sbuf_new();
    t->control = sbuf_new();
    t->payload = 0;
    t->codec = sbuf_new();
    t->codec_param = sbuf_new();
    t->sample_rate = 0;
    t->fmtp = sbuf_new();
    INIT_LIST_HEAD(&t->link);
    return t;
}

void sdp_track_del(sdp_track_t *t)
{
    sbuf_del(t->type);
    free(t);
}

sdp_track_t *sdp_get_video_track(sdp_t *sdp)
{
    return find_track(sdp, "video");
}
sdp_track_t *sdp_get_audio_track(sdp_t *sdp)
{
    return find_track(sdp, "audio");
}
const char *sdp_track_get_type(sdp_track_t *trak)
{
    return trak->type->data;
}
const char *sdp_track_get_control(sdp_track_t *trak)
{
    return trak->control->data;
}
const char *sdp_track_get_codec(sdp_track_t *trak)
{
    return trak->codec->data;
}
const char *sdp_track_get_codec_param(sdp_track_t *trak)
{
    return trak->codec_param->data;
}
const char *sdp_track_get_fmtp(sdp_track_t *trak)
{
    return trak->fmtp->data;
}
int sdp_track_get_index(sdp_track_t *trak)
{
    return trak->index;
}
int sdp_track_get_payload(sdp_track_t *trak)
{
    return trak->payload;
}
int sdp_track_get_sample_rate(sdp_track_t *trak)
{
    return trak->sample_rate;
}

sdp_track_t *find_track(sdp_t *sdp, const char *type)
{
    sdp_track_t *trak;
    list_for_each_entry(trak, &sdp->track_list, link) {
        if (strcmp(trak->type->data, type) == 0)
            return trak;
    }
    return NULL;
}
