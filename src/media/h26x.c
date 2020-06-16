#include "h26x.h"
#include "sbuf.h"
#include "pack_util.h"
#include <stdlib.h>
#include <string.h>

static const char *find_nalu_end(const char *data, size_t size);

int extract_h26x_nalus(const char *data, size_t size, nalu_part_t *units, int max_units)
{
    int n = 0, i;
    for (i = 0; i < max_units; ++i) {
        if (size <= 0)
            break;
        nalu_part_t *u = units + i;
        if (size >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) {
            u->data = data + 4;
            data += 4;
            size -= 4;
        } else if (size >= 3 && data[0] == 0 && data[1] == 0 && data[2] == 1) {
            u->data = data + 3;
            data += 3;
            size -= 3;
        } else {
            u->data = data;
        }
        const char *nalu_end = find_nalu_end(data, size);
        u->size = nalu_end - (const char*)u->data;
        data += u->size;
        size -= u->size;
        ++n;
    }
    return n;
}

sbuf_t *make_h264_decoder_config_record(const char *sps_data, size_t sps_size,
                                        const char *pps_data, size_t pps_size)
{
    if (sps_size < 4 || pps_size == 0)
        return NULL;
    sbuf_t *buf = sbuf_new1(12 + sps_size + pps_size);
    sbuf_appendc(buf, 1); // config version
    sbuf_append2(buf, sps_data + 1, 3);
    sbuf_appendc(buf, 0xff);
    sbuf_appendc(buf, 0xe1); // num_sps
    sbuf_appendc(buf, (sps_size >> 8) & 0xff);
    sbuf_appendc(buf, sps_size & 0xff);
    sbuf_append2(buf, sps_data, sps_size);
    sbuf_appendc(buf, 1); // num_pps
    sbuf_appendc(buf, (pps_size >> 8) & 0xff);
    sbuf_appendc(buf, pps_size & 0xff);
    sbuf_append2(buf, pps_data, pps_size);
    return buf;
}

int update_h264_decoder_config_record(sbuf_t *config, const char *new_sps_data, size_t new_sps_size,
                                      const char *new_pps_data, size_t new_pps_size)
{
    if (sbuf_empty(config))
        return 0;
    int sps_size = unpack_be16(config->data + 6);
    sbuf_t *sps = sbuf_strndup(config->data + 8, sps_size);
    int pps_size = unpack_be16(config->data + 8 + sps_size + 1);
    sbuf_t *pps = sbuf_strndup(config->data + 8 + sps_size + 3, pps_size);

    int changed;
    if (new_sps_size == (size_t)sps->size && new_pps_size == (size_t)pps->size
        && !memcmp(new_sps_data, sps->data, new_sps_size)
        && !memcmp(new_sps_data, sps->data, new_sps_size)) {

        changed = 0;
    } else {
        sbuf_t *new_config = make_h264_decoder_config_record(new_sps_data, new_sps_size,
                                                             new_pps_data, new_pps_size);
        sbuf_strncpy(config, new_config->data, new_config->size);
        sbuf_del(new_config);
        changed = 1;
    }
    sbuf_del(sps);
    sbuf_del(pps);
    return changed;
}

const char *find_nalu_end(const char *data, size_t size)
{
    const char *data_end = data + size;
    while (data + 3 <= data_end) {
        if (data[0] == 0 && data[1] == 0 && (data[2] == 0 || data[2] == 1)) {
            return data;
        } else {
            ++data;
        }
    }
    return data_end;
};
