/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _CIPHER_H
#define _CIPHER_H

#include "common.h"
#include "twofish.h"
#include "rijndael-api-fst.h"

#define AES_BLOCK_SIZE 16

#define CIPHER_NONE 0
#define CIPHER_TWOFISH 1
#define CIPHER_AES 2

#define MODE_ECB 0
#define MODE_XTS 1

#define PADDING_NONE 1 /* Only use this if you always encrypt multiples of 
                        * block size*/

typedef union internalKey {
    tf_key twofish_key;
    struct aes_keys {
        rijndaelKeyInstance enc_key;
        rijndaelKeyInstance dec_key;
    } aes_keys;
} internalKeyUnion;

typedef union internalContext{
    rijndaelCipherInstance aes_ctx;
} internalContextUnion;

typedef struct cipherContext {
    uint cipher;
    uint mode;
    uint padding;
    void* mode_extra;
    uint mode_extra_len;
    internalKeyUnion internalKey;
    internalContextUnion internalContext;
    uint blockSize;

    /* Second set of internals for XTS mode */
    internalKeyUnion internalKey2;
    internalContextUnion internalContext2;
} cipherContext;

typedef void(*enc_dec_cb)(cipherContext*, uchar*, uint,uchar*,uint,uint);

int cipher_init(uint cipher, uint mode, uint padding, cipherContext* ctx);

int cipher_set_key(cipherContext* ctx, uchar* key, uint keylen);

int cipher_set_set_iv(cipherContext* ctx, uchar* iv);

int cipher_encrypted_len(cipherContext *ctx, uchar* msg, uint msg_len, 
                              uint* result);
int cipher_decrypted_len(cipherContext* ctx, uchar* msg, uint msg_len,
                              uint* result);
int cipher_encrypt(cipherContext *ctx, uchar* msg, uint msg_len, 
                        uchar* dst, uint* result);
int cipher_decrypt(cipherContext *ctx, uchar* msg, uint msg_len, 
                        uchar* dst, uint* result);

#endif
