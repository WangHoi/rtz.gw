#pragma once
#include <stddef.h>

/**
 * @param  ibuf
 * @param  ilen
 * @param  obuf         NULL to measure output string length
 * @param  max_osize
 * @return size_t       output string length
 */
size_t base64_encode(const void *ibuf, size_t ilen, char* obuf, size_t max_osize);

