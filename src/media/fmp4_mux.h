#pragma once
#include <stdint.h>

typedef struct sbuf_t sbuf_t;

/**
 * generate init segment
 * \param   idx     0=video,1=audio
 * \param   data    video: AVCDecoderConfigurationRecord
 *                  audio: FLACSpecificBox
 */
sbuf_t *fmp4_mux_init_seg(unsigned idx, const char *data, int size);

/**
 * only accept H264_IFRAME and H264_PFRAME
 * \param   idx     0=video,1=audio
 * \param   data    NALU without 4-bytes header
 */
sbuf_t *fmp4_mux_media_seg(unsigned idx, unsigned seq,
                           int64_t pts, int32_t duration,
                           int key_frame, const char *data, int size);
