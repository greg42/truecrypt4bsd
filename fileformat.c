/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#include "common.h"
#include "cipher.h"
#include "hash.h"
#include "mac.h"
#include "pbkdf2.h"
#include "fileformat.h"
#include "hexdump.h"
#include "xts.h"
#include "crc32.h"
#include <sys/types.h>
#include <machine/endian.h>
#include <string.h>

/* Decrypt a sector *IN PLACE* */
int tc_decryptSector(uchar* sector, uint sector_len, lba_type lba,
                     cipherContext* cc1, cipherContext* cc2,
                     cipherContext* cc3) {
    uint res;
    lba_type l;

    if (cc1->cipher == CIPHER_NONE)
        return 2;

    l = lba;
    cc1->mode_extra = &l;
    cipher_decrypt(cc1, sector, sector_len, sector, &res);

    if (cc2->cipher != CIPHER_NONE) {
        cc2->mode_extra = &l;
        cipher_decrypt(cc2, sector, sector_len, sector, &res);
        if (cc3->cipher != CIPHER_NONE) {
            cc3->mode_extra = &l;
            cipher_decrypt(cc3, sector, sector_len, sector, &res);
        }
    }
    return 0;
}

/* Encrypt a sector *IN PLACE* */
int tc_encryptSector(uchar* sector, uint sector_len, lba_type lba,
                          cipherContext* cc1, cipherContext* cc2,
                          cipherContext* cc3) {
    uint res;
    lba_type l;

    l = lba;

    if ((cc3->cipher != CIPHER_NONE && cc2->cipher == CIPHER_NONE) ||
        cc1->cipher == CIPHER_NONE)
        return 2;

    if (cc3->cipher != CIPHER_NONE) {
        cc3->mode_extra = &l;
        cipher_encrypt(cc3, sector, sector_len, sector, &res);
    }

    if (cc2->cipher != CIPHER_NONE) {
        cc2->mode_extra = &l;
        cipher_encrypt(cc2, sector, sector_len, sector, &res);
    }

    cc1->mode_extra = &l;
    cipher_encrypt(cc1, sector, sector_len, sector, &res);

    return 0;
}


/* Set up a cipher (cascade) for decrypting the actual data within
 * a TC container.
 */
int tc_cipherSetup(uchar* pass, uint plen, uchar* header, uint hdr_len, 
                   cipherContext* cc1,
                   cipherContext* cc2, cipherContext* cc3, qword* start,
                   qword* len) {

    uint ciphers[] = {CIPHER_NONE, CIPHER_AES, CIPHER_TWOFISH, CIPHER_SERPENT};
    /* TODO: Implement the missing algorithms */
    uint hashes[] = {HASH_RIPEMD_160, HASH_SHA512, HASH_WHIRLPOOL};

    uint cipher1, cipher2, cipher3;
    uint hash;
    uint ci1, ci2, ci3, hi;
    uchar go;
    int res;
    uchar buf[SECTORSIZE];
    uchar* keys;
    uint ciphersUsed;
    uchar key1[2*KEYLEN];
    uchar key2[2*KEYLEN];
    uchar key3[2*KEYLEN];
    
    cipher1 = cipher2 = cipher3 = CIPHER_NONE;
    go = 1;
    /* Loop through all possible ciphers and hashes */
    for (ci3 = 0; go && ci3 < arrlen(ciphers); ci3++)
        /* If cipher3 is used, cipher 2 cannot be unused. */
        for (ci2 = ci3?1:0; go && ci2 < arrlen(ciphers); ci2++)
            for (ci1 = 1; go && ci1 < arrlen(ciphers); ci1++) 
                for (hi = 0; go && hi < arrlen(hashes); hi++) {
                    cipher1 = ciphers[ci1];
                    cipher2 = ciphers[ci2];
                    cipher3 = ciphers[ci3];
                    hash = hashes[hi];

                    res = decrypt_hdr_try(pass, plen, header, FF_SALT_LEN, 
                              header+FF_SALT_LEN, hdr_len - FF_SALT_LEN, hash, 
                              cipher1, cipher2, cipher3, buf, sizeof(buf));
                    /* Success? */
                    if (res == 0) 
                        go = 0;
                }
    /* Didn't work out :( */
    if (go)
        return -1;

    ciphersUsed = 0;
    if (cipher1 != CIPHER_NONE)
        ciphersUsed++;
    if (cipher2 != CIPHER_NONE)
        ciphersUsed++;
    if (cipher3 != CIPHER_NONE)
        ciphersUsed++;
    
    /* Initialize the user supplied ciphers */
    cipher_init(cipher1, MODE_XTS, PADDING_NONE, cc1);
    cipher_init(cipher2, MODE_XTS, PADDING_NONE, cc2);
    cipher_init(cipher3, MODE_XTS, PADDING_NONE, cc3);

    keys = buf + FF_KEY_OFFSET - FF_SALT_LEN;
    /* Set up the keys */
    if (ciphersUsed == 1) {
        memcpy(key1, keys, KEYLEN);
        memcpy(key1+KEYLEN, keys + ciphersUsed*KEYLEN, KEYLEN);
        cipher_set_key(cc1, key1, 2*KEYLEN);
    }
    else if (ciphersUsed == 2) {
        memcpy(key2, keys, KEYLEN);
        memcpy(key2+KEYLEN, keys + ciphersUsed*KEYLEN, KEYLEN);

        memcpy(key1, keys+KEYLEN, KEYLEN);
        memcpy(key1+KEYLEN, keys + ciphersUsed*KEYLEN + KEYLEN, KEYLEN);

        cipher_set_key(cc1, key1, 2*KEYLEN);
        cipher_set_key(cc2, key2, 2*KEYLEN);
    }
    else if (ciphersUsed == 3) {
        memcpy(key3, keys, KEYLEN);
        memcpy(key3+KEYLEN, keys + ciphersUsed*KEYLEN, KEYLEN);

        memcpy(key2, keys+KEYLEN, KEYLEN);
        memcpy(key2+KEYLEN, keys + ciphersUsed*KEYLEN + KEYLEN, KEYLEN);

        memcpy(key1, keys+2*KEYLEN, KEYLEN);
        memcpy(key1+KEYLEN, keys + ciphersUsed*KEYLEN + 2*KEYLEN, KEYLEN);

        cipher_set_key(cc1, key1, 2*KEYLEN);
        cipher_set_key(cc2, key2, 2*KEYLEN);
        cipher_set_key(cc3, key3, 2*KEYLEN);
    }
    else
        return 2;

    *start = betoh64( *((qword*)(buf + FF_DATA_START - FF_SALT_LEN )) );
    *len   = betoh64( *((qword*)(buf + FF_DATA_LEN - FF_SALT_LEN )) );
    return 0;
}

int decrypt_hdr_try(uchar* pass, uint plen, uchar* salt, uint slen, 
                    uchar* plain, uint plainlen, uint hash, uint cipher1, 
                    uint cipher2, uint cipher3,uchar* dst,uint wantBytes) {
    hash_ctx hc;
    hash_ctx* h;
    uint c;
    uint dklen;
    uchar* dk;
    uchar* buf;
    cipherContext cctx1, cctx2, cctx3;
    uint ciphersUsed;
    uint res;
    lba_type lba;
    uint crc32_1;
    uchar* tmp;
    /* Buffers for the XTR keys */
    uchar key1[2*KEYLEN];
    uchar key2[2*KEYLEN];
    uchar key3[2*KEYLEN];

    if (cipher1 == CIPHER_NONE)
        return 2;

    h = &hc;
    hash_init(h, hash);
    if (hash == HASH_RIPEMD_160)
        c = 2000;
    else
        c = 1000;
    
    /* 256 bit are the key length if only one cipher is used */
    dklen = KEYLEN;
    ciphersUsed = 1;
    if (cipher2 != CIPHER_NONE) {
        dklen += KEYLEN;
        ciphersUsed++;
    }
    if (cipher3 != CIPHER_NONE) {
        dklen += KEYLEN;
        ciphersUsed++;
        if (cipher2 == CIPHER_NONE)
            return 2;
    }
    /* For XTS mode, we need the double amount of key material */
    dklen *= 2;
    lba = 0;
    dk = (uchar*)malloc(dklen);
    if (dk == NULL) {
        return 1;
    }
    /* Get the key */
    pbkdf2(h, pass, plen, salt, slen, c, dklen, dk);
    /* Split up the derived key */
    if (ciphersUsed == 1) {
        memcpy(key1, dk, KEYLEN);
        memcpy(key1+KEYLEN, dk + ciphersUsed*KEYLEN, KEYLEN);
        cipher_init(cipher1, MODE_XTS, PADDING_NONE, &cctx1);
        cctx1.mode_extra = &lba;
        cipher_set_key(&cctx1, key1, 2*KEYLEN);
    }
    else if (ciphersUsed == 2) {
        memcpy(key2, dk, KEYLEN);
        memcpy(key2+KEYLEN, dk + ciphersUsed*KEYLEN, KEYLEN);

        memcpy(key1, dk+KEYLEN, KEYLEN);
        memcpy(key1+KEYLEN, dk + ciphersUsed*KEYLEN + KEYLEN, KEYLEN);

        cipher_init(cipher1, MODE_XTS, PADDING_NONE, &cctx1);
        cctx1.mode_extra = &lba;
        cipher_set_key(&cctx1, key1, 2*KEYLEN);

        cipher_init(cipher2, MODE_XTS, PADDING_NONE, &cctx2);
        cctx2.mode_extra = &lba;
        cipher_set_key(&cctx2, key2, 2*KEYLEN);

    } else {
        memcpy(key3, dk, KEYLEN);
        memcpy(key3+KEYLEN, dk + ciphersUsed*KEYLEN, KEYLEN);

        memcpy(key2, dk+KEYLEN, KEYLEN);
        memcpy(key2+KEYLEN, dk + ciphersUsed*KEYLEN + KEYLEN, KEYLEN);

        memcpy(key1, dk+2*KEYLEN, KEYLEN);
        memcpy(key1+KEYLEN, dk + ciphersUsed*KEYLEN + 2*KEYLEN, KEYLEN);

        cipher_init(cipher1, MODE_XTS, PADDING_NONE, &cctx1);
        cctx1.mode_extra = &lba;
        cipher_set_key(&cctx1, key1, 2*KEYLEN);

        cipher_init(cipher2, MODE_XTS, PADDING_NONE, &cctx2);
        cctx2.mode_extra = &lba;
        cipher_set_key(&cctx2, key2, 2*KEYLEN);

        cipher_init(cipher3, MODE_XTS, PADDING_NONE, &cctx3);
        cctx3.mode_extra = &lba;
        cipher_set_key(&cctx3, key3, 2*KEYLEN);
    }
    free(dk);
    
    /* TODO: Actually, one wants ask how many bytes this is going to
     *       need by calling cipher_decrypted_len? */ 
    buf = (uchar*)malloc(plainlen);
    if (buf == NULL) {
        return 1;
    }
    memset(buf, 0, plainlen);
    cipher_decrypt(&cctx1, plain, plainlen, buf, &res);
    if (cipher2 != CIPHER_NONE) {
        cipher_decrypt(&cctx2, buf, plainlen, buf, &res);
    }
    if (cipher3 != CIPHER_NONE) {
        cipher_decrypt(&cctx3, buf, plainlen, buf, &res);
    }
    
    if (buf[0] != 'T' ||
        buf[1] != 'R' ||
        buf[2] != 'U' ||
        buf[3] != 'E') {
        free(buf);
        return -1;
    }
    
    crc32_1 = crc32(buf + plainlen - 256, 256);
    tmp = (uchar*)(&crc32_1);
    /* TODO: CRC value endianess? */
    if (buf[ 8] != tmp[3] ||
        buf[ 9] != tmp[2] ||
        buf[10] != tmp[1] ||
        buf[11] != tmp[0]) {
        free(buf);
        return -1;
    }
    
    /* Hurray, we did it. */

    memcpy(dst, buf, wantBytes);

    free(buf);
    return 0;
}
