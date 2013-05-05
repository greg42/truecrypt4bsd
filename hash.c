/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#include <string.h>
#include "common.h"
#include "hash.h"
#include "rmd160.h"
#include "sha1.h"
#include "crc32.h"

int hash_init(hash_ctx* h, uint hashtype) {
    if (hashtype > HASH_MAX)
        return 2;
    h->type = hashtype;
    switch(h->type) {
        case HASH_RIPEMD_160:
            h->blocksize = 64;
            h->outsize = 20;
            rmd160_init(h);
            break;
        case HASH_SHA1:
            h->blocksize = 64;
            h->outsize = 20;
            sha1_init(h);
            break;
        case HASH_SHA512:
            h->blocksize = 128;
            h->outsize = 64;
            my_sha512_init(h);
            break;
        case HASH_WHIRLPOOL:
            h->blocksize = 64;
            h->outsize = 64;
            whirlpool_init(h);
            break;
        case HASH_INSECURE_CRC32:
            h->blocksize = 1;
            h->outsize = 4;
            crc32_init(h);
        default:
            return 2;
    }
    return 0;
}

int hash_add(hash_ctx* h, uchar* msg, uint msglen) {
    if (h->type > HASH_MAX)
        return 0;
    switch(h->type) {
        case HASH_RIPEMD_160:
            rmd160_add(h, msg, msglen);
            break;
        case HASH_SHA1:
            sha1_add(h, msg, msglen);
            break;
        case HASH_SHA512:
            my_sha512_add(h, msg, msglen);
            break;
        case HASH_WHIRLPOOL:
            whirlpool_add(h, msg, msglen * 8);
            break;
        case HASH_INSECURE_CRC32:
            for (int i = 0; i < msglen; i++)
                crc32_add(h, msg[i]);
            break;
        default:
            return 2;
    }
    return 0;
}

int hash_final(hash_ctx* h, uchar* out) {
    if (h->type > HASH_MAX)
        return 2;
    switch(h->type) {
        case HASH_RIPEMD_160:
            rmd160_final(h, out);
            break;
        case HASH_SHA1:
            sha1_final(h, out);
            break;
        case HASH_SHA512:
            my_sha512_final(h, out);
            break;
        case HASH_WHIRLPOOL:
            whirlpool_final(h, out);
            break;
        case HASH_INSECURE_CRC32:
            crc32_final(h);
            *((uint32_t*)out) = h->internalContext.crc32;
            break;
        default:
            return 2;
    }
    return 0;
}


int hash(hash_ctx* h, uchar* msg, uint msglen, uchar* out) {
    int res = 0;
    if ((res = hash_init(h, h->type)) != 0) return res;
    if ((res = hash_add(h, msg, msglen)) != 0) return res;
    if ((res = hash_final(h, out)) != 0) return res;

    return res;
}

