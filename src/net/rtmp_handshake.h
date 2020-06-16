#pragma once

typedef struct rtmp_hs_t rtmp_hs_t;

rtmp_hs_t *rtmp_hs_new();
void rtmp_hs_del(rtmp_hs_t *hs);
void rtmp_hs_set_c1(rtmp_hs_t *hs, const void *data);
const void *rtmp_hs_generate_s1(rtmp_hs_t *hs);
const void *rtmp_hs_generate_s2(rtmp_hs_t *hs);
