/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#include <stdlib.h>
#include <string.h>
#include "common.h"
#include "mac.h"
#include "hash.h"

int mac_init(uint type, uchar* sendkey, uint sendkeylen, uchar* recvkey,
                  uint recvkeylen, void* data, macContext* mc) {
    mc->sendkey = sendkey;
    mc->recvkey = recvkey;
    mc->data = data;
    mc->mactype = type;
    mc->sendkeylen = sendkeylen;
    mc->recvkeylen = recvkeylen;
    return 0;
}

int mac_size(macContext* mc, uint* ms) {
    switch(mc->mactype) {
        case MAC_HMAC:
            *ms = ((hash_ctx*)mc->data)->outsize;
            return 0;
        default:
            return 2;
    }
    return 2;
}

int mac_calc(macContext* mc, uchar* msg, uint msglen, uchar* res) {
    int ret = 0;

    switch(mc->mactype) {
        case MAC_HMAC:
            if ((ret = hmac((hash_ctx*)mc->data, mc->sendkey, mc->sendkeylen,
                           msg, msglen, res)) != 0) 
                return ret;
            return 0;
        default:
            return 2;
    }
    return 2;
}

int mac_verify(macContext* mc, uchar* msg, uint msglen, uchar* mac) {
    uint ms;
    uchar* buf;
    uchar* tmp;

    if (mac_size(mc, &ms) != 0)
        return 2;
    buf = (uchar*)malloc(ms);
    if (buf == null)
        return 1;
    switch(mc->mactype) {
        case MAC_HMAC:
            tmp = mc->recvkey;
            mc->recvkey = mc->sendkey;
            if (mac_calc(mc, msg, msglen, buf) != 0)
                return 2;
            mc->recvkey = tmp;
            if (memcmp(buf, mac, ms) == 0)
                return 0;
            return -1;
        default:
            return 2;
    }
    return 2;
}

int hmac(hash_ctx* h, uchar* key, uint keylen, uchar* msg, uint msglen, 
              uchar* res) {
    int ret = 0;

    uchar* opad = (uchar*)malloc(h->blocksize);
    uchar* ipad = (uchar*)malloc(h->blocksize);
    uchar* k    = (uchar*)malloc(h->blocksize);
    uint klen = 0;
    uint i = 0;
    uchar* buf = (uchar*)malloc(h->blocksize);

    memset(k, 0, h->blocksize);

    if (opad == null || ipad == null || k == null || buf == null) {
        return 1;
    }
    memset(opad, 0x5c, h->blocksize);
    memset(ipad, 0x36, h->blocksize);
    if (keylen > h->blocksize) {
        if (hash(h, key, keylen, k) != 0)
            return 2;
        klen = h->outsize;
    }
    else {
        memcpy(k, key, keylen);
        klen = keylen;
    }
    for (i = 0; i < klen; i++) {
        opad[i] ^= k[i];
        ipad[i] ^= k[i];
    }
    if ((ret = hash_init(h, h->type)) != 0) goto out;
    if ((ret = hash_add(h, ipad, h->blocksize)) != 0) goto out;
    if ((ret = hash_add(h, msg, msglen)) != 0) goto out;
    if ((ret = hash_final(h, buf)) != 0) goto out;
    if ((ret = hash_init(h, h->type)) != 0) goto out;
    if ((ret = hash_add(h, opad, h->blocksize)) != 0) goto out;
    if ((ret = hash_add(h, buf, h->outsize)) != 0) goto out;
    if ((ret = hash_final(h, res)) != 0) goto out;

    out:
    free(k);
    free(buf);
    free(opad);
    free(ipad);

    return ret;
}
