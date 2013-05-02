/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _FILEFORMAT_H
#define _FILEFORMAT_H

/* Truecrypt always uses 256 bit keys */
#define KEYLEN 32

#include "types.h"
#include "hash.h"
#include "mac.h"
#include "cipher.h"
#include "pbkdf2.h"
#include "xts.h"

#define SECTORSIZE 512

#define FF_SALT_LEN 64
#define FF_TRUE_LEN  4
#define FF_KEY_OFFSET 256
#define FF_DATA_START 108
#define FF_DATA_LEN 116

int tc_decryptSector(uchar* sector, uint sector_len, lba_type lba,
                          cipherContext* cc1, cipherContext* cc2,
                          cipherContext* cc3);

int tc_encryptSector(uchar* sector, uint sector_len, lba_type lba,
                          cipherContext* cc1, cipherContext* cc2,
                          cipherContext* cc3);


int tc_cipherSetup(uchar* pass, uint plen, uchar* header, uint hdr_len,
                        cipherContext* cc1,
                        cipherContext* cc2, cipherContext* cc3, qword* start,
                        qword* len);

int decrypt_hdr_try(uchar* pass, uint plen, uchar* salt, uint slen,
                         uchar* plain, uint plainlen, uint hash, uint cipher1,
                         uint cipher2, uint cipher3,uchar* dst,uint wantBytes);


#endif
