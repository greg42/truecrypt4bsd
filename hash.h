/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _HASH_H
#define _HASH_H

#include "common.h"

#define HASH_MAX 2
#define HASH_RIPEMD_160 0
#define HASH_SHA1 1
#define HASH_SHA512 2

#include "rmd160.h"
#include "sha1.h"
#include "sha2.h"

typedef union h_internalContextUnion {
    rmd160_ctx rmd;
    SHA1Context sha1;
    sha512_ctx sha512;
} h_internalContextUnion;

typedef struct hash_ctx {
    uint blocksize;
    uint type;
    uint outsize;
    h_internalContextUnion internalContext;
} hash_ctx;

#include "hash_api.h"

int hash_init(hash_ctx* h, uint hashtype);
int hash_add(hash_ctx* h, uchar* msg, uint msglen);
int hash_final(hash_ctx* h, uchar* out);
int hash(hash_ctx* h, uchar* msg, uint msglen, uchar* out);

#endif
