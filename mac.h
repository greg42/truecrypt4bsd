/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _MAC_H
#define _MAC_H

#include "common.h"
#include "hash.h"

#define MAC_HMAC 0

typedef struct macContext {
    uint mactype;
    uchar* sendkey;
    uchar* recvkey;
    uint sendkeylen;
    uint recvkeylen;
    void* data; /* The data needed for the MAC. For HMAC this is the hash ctx */
} macContext;

int mac_init(uint type, uchar* sendkey, uint sendkeylen, uchar* recvkey,
                  uint recvkeylen, void* data, macContext* mc);
int mac_size(macContext* mc, uint* ms);
int mac_calc(macContext* mc, uchar* msg, uint msglen, uchar* res);
int mac_verify(macContext* mc, uchar* msg, uint msglen, uchar* mac);
int hmac(hash_ctx* h, uchar* key, uint keylen, uchar* msg, uint msglen,
              uchar* res);
#endif
