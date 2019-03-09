#include "pack_util.h"

uint64_t unpack_be64(const void *data)
{
    const uint8_t *p = data;
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
        | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

uint32_t unpack_be32(const void *data)
{
    const uint8_t *p = data;
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint32_t unpack_be24(const void *data)
{
    const uint8_t *p = data;
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

uint16_t unpack_be16(const void *data)
{
    const uint8_t *p = data;
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

size_t pack_be64(void *data, uint64_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)((n & 0xff00000000000000) >> 56);
    p[1] = (uint8_t)((n & 0xff000000000000) >> 48);
    p[2] = (uint8_t)((n & 0xff0000000000) >> 40);
    p[3] = (uint8_t)((n & 0xff00000000) >> 32);
    p[4] = (uint8_t)((n & 0xff000000) >> 24);
    p[5] = (uint8_t)((n & 0xff0000) >> 16);
    p[6] = (uint8_t)((n & 0xff00) >> 8);
    p[7] = (uint8_t)(n & 0xff);
    return 8;
}

size_t pack_be32(void *data, uint32_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)((n & 0xff000000) >> 24);
    p[1] = (uint8_t)((n & 0xff0000) >> 16);
    p[2] = (uint8_t)((n & 0xff00) >> 8);
    p[3] = (uint8_t)(n & 0xff);
    return 4;
}

size_t pack_be24(void *data, uint32_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)((n & 0xff0000) >> 16);
    p[1] = (uint8_t)((n & 0xff00) >> 8);
    p[2] = (uint8_t)(n & 0xff);
    return 3;
}

size_t pack_be16(void *data, uint16_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)((n & 0xff00) >> 8);
    p[1] = (uint8_t)(n & 0xff);
    return 2;
}

uint32_t unpack_le32(const void *data)
{
    const uint8_t *p = data;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

size_t pack_le32(void *data, uint32_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)(n & 0xff);
    p[1] = (uint8_t)((n & 0xff00) >> 8);
    p[2] = (uint8_t)((n & 0xff0000) >> 16);
    p[3] = (uint8_t)((n & 0xff000000) >> 24);
    return 4;
}

uint16_t unpack_le16(const void *data)
{
    const uint8_t *p = data;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

size_t pack_le16(void *data, uint16_t n)
{
    uint8_t *p = data;
    p[0] = (uint8_t)(n & 0xff);
    p[1] = (uint8_t)((n & 0xff00) >> 8);
    return 2;
}
