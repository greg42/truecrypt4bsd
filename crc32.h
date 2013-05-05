#ifndef _CRC32_H
#define _CRC32_H

#include "hash.h"

unsigned long crc32(const unsigned char *s, unsigned int len);

void crc32_init(hash_ctx* h);
void crc32_add(hash_ctx* h, uint8_t b);
void crc32_final(hash_ctx* h);

#endif

