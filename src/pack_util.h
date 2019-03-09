#pragma once
#include <stddef.h>
#include <stdint.h>

uint64_t unpack_be64(const void *data);
uint32_t unpack_be32(const void *data);
uint32_t unpack_be24(const void *data);
uint16_t unpack_be16(const void *data);
size_t pack_be16(void *data, uint16_t n);
size_t pack_be24(void *data, uint32_t n);
size_t pack_be32(void *data, uint32_t n);
size_t pack_be64(void *data, uint64_t n);

uint32_t unpack_le32(const void *data);
uint16_t unpack_le16(const void *data);
size_t pack_le32(void *data, uint32_t n);
size_t pack_le16(void *data, uint16_t n);
