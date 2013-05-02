/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _PBKDF2_H
#define _PBKDF2_H

#include "types.h"
#include "hash.h"

int pbkdf2(hash_ctx* hc, uchar* p, dword plen, uchar* s, dword slen,
                dword c, dword dklen, uchar* dk);

#endif
