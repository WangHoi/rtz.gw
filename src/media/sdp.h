#pragma once
#include <stddef.h>

typedef struct sdp_t sdp_t;
typedef struct sdp_track_t sdp_track_t;

sdp_t *sdp_new();
void sdp_del(sdp_t *sdp);
int sdp_valid(sdp_t *sdp);
int sdp_parse(sdp_t *sdp, const char *data);
sdp_track_t *sdp_get_video_track(sdp_t *sdp);
sdp_track_t *sdp_get_audio_track(sdp_t *sdp);
const char *sdp_track_get_type(sdp_track_t *trak);
const char *sdp_track_get_control(sdp_track_t *trak);
const char *sdp_track_get_codec(sdp_track_t *trak);
const char *sdp_track_get_codec_param(sdp_track_t *trak);
const char *sdp_track_get_fmtp(sdp_track_t *trak);
int sdp_track_get_index(sdp_track_t *trak);
int sdp_track_get_payload(sdp_track_t *trak);
int sdp_track_get_sample_rate(sdp_track_t *trak);
