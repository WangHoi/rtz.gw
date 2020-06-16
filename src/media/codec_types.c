#include "codec_types.h"
#include "sbuf.h"
#include <stdlib.h>
#include <string.h>

enum {
    MAX_XPS_SIZE = 4 * 1024,
};

video_codec_t *video_codec_new()
{
    video_codec_t *codec = malloc(sizeof(video_codec_t));
    memset(codec, 0, sizeof(video_codec_t));
    codec->type = INVALID_VIDEO_CODEC;
    codec->time_base = 90000;
    codec->frame_rate = 25;
    codec->vps_data = sbuf_new(MAX_XPS_SIZE);
    codec->sps_data = sbuf_new(MAX_XPS_SIZE);
    codec->pps_data = sbuf_new(MAX_XPS_SIZE);
    return codec;
}
void video_codec_del(video_codec_t *codec)
{
    sbuf_del(codec->vps_data);
    sbuf_del(codec->sps_data);
    sbuf_del(codec->pps_data);
    free(codec);
}
void video_codec_reset(video_codec_t *codec)
{
    codec->type = INVALID_VIDEO_CODEC;
    codec->time_base = 90000;
    codec->frame_rate = 25;
    sbuf_clear(codec->vps_data);
    sbuf_clear(codec->sps_data);
    sbuf_clear(codec->pps_data);
}
audio_codec_t *audio_codec_new()
{
    audio_codec_t *codec = malloc(sizeof(audio_codec_t));
    memset(codec, 0, sizeof(audio_codec_t));
    codec->type = INVALID_AUDIO_CODEC;
    codec->sample_rate = 8000;
    codec->bits_per_sample = 8;
    codec->num_channels = 1;
    return codec;
}
void audio_codec_del(audio_codec_t *codec)
{
    free(codec);
}
void audio_codec_reset(audio_codec_t *codec)
{
    codec->type = INVALID_AUDIO_CODEC;
    codec->sample_rate = 8000;
    codec->bits_per_sample = 0;
    codec->num_channels = 1;
}
