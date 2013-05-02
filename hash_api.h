/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _HASH_API_H
#define _HASH_API_H
#include "hash.h"

int8_t rmd160_init(hash_ctx* h);
int8_t rmd160_add(hash_ctx* h, uchar* msg, uint msglen);
int8_t rmd160_final(hash_ctx* h, uchar* out);

uint8_t sha1_init(hash_ctx* h);
uint8_t sha1_add(hash_ctx* h, uchar* msg, uint msg_len);
uint8_t sha1_final(hash_ctx* h, uchar* out);

uint8_t my_sha512_init(hash_ctx* h);
uint8_t my_sha512_add(hash_ctx* h, uchar* msg, uint msglen);
uint8_t my_sha512_final(hash_ctx* h, uchar* out);

#endif
