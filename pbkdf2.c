/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#include <string.h>

#include "types.h"
#include "mac.h"
#include "hash.h"
#include <arpa/inet.h>

/* Limitation: this function only works with hmac hashes as PRF */
int pbkdf2(hash_ctx* hc, uchar* p, dword plen, uchar* s, dword slen,
           dword c, dword dklen, uchar* dk) {
    dword hlen = 0;
    dword l = 0;
    dword i = 0;
    dword j = 0;
    uchar* out = NULL;
    uchar* buf = NULL;
    uchar* buf2 = NULL;
    dword b2len = 0;
    dword k = 0;

    hlen = hc->outsize;
    l = (dklen / hlen) + (dklen % hlen ? 1:0);

    out = (uchar*)malloc(hlen * l);
    if (out == NULL) {
        return 1;
    }
    buf = (uchar*)malloc(hlen);
    if (buf == NULL) {
        free(out);
        return 1;
    }
    buf2 = (uchar*)malloc(slen + 4);
    if (buf2 == NULL) {
        free(out);
        free(buf);
        return 1;
    }
    memset(out, 0, hlen * l);
    for (i = 1; i <= l; i++) {
        memcpy(buf2, s, slen);
        (*(uint*)(buf2 + slen)) = htonl(i);
        b2len = slen + 4;
        for (j = 0; j < c; j++) {
            hmac(hc, p, plen, buf2, b2len, buf);
            for (k = 0; k < hlen; k++) {
                out[hlen*(i-1) + k] ^= buf[k];
            }
            memcpy(buf2, buf, hlen);
            b2len = hlen;
        }
    }
    memcpy(dk, out, dklen);
    return 0;
}
