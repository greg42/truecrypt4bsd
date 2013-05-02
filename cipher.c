/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */

#include "cipher.h"
#include "twofish.h"
#include "xts.h"
#include "rijndael-api-fst.h"

#include <string.h>

/* Return an uint >= the length of encrypted msg. */
int cipher_encrypted_len(cipherContext *ctx, uchar* msg, uint msg_len, 
                         uint* result) {
    switch(ctx->cipher) {
        case CIPHER_NONE:
            *result = msg_len;
            return 0;
        default:
            return 2;
    }
    return 2;
}

/* Return an uint >= the length of decrypted msg. */
int cipher_decrypted_len(cipherContext* ctx, uchar* msg, uint msg_len,
                              uint* result) {
    switch(ctx->cipher) {
        case CIPHER_NONE:
            *result = msg_len;
            return 0;
        default:
            return 2;
    }
    return 2;
}

int cipher_init(uint cipher, uint mode, uint padding, cipherContext* ctx) {
    int i, iterations;
    internalContextUnion* ic = NULL;

    /* In XTS mode we actually have two ciphers. */
    if (mode == MODE_XTS)
        iterations = 2;
    else
        iterations = 1;

    for (i = 0; i < iterations; i++) {
        if (i == 0)
            ic = &(ctx->internalContext);
        else if (i == 1)
            ic = &(ctx->internalContext2);
        switch(cipher) {
            case CIPHER_NONE:
                ctx->cipher = CIPHER_NONE;
                ctx->blockSize = 1;
                break;
            case CIPHER_AES:
                rijndael_cipherInit(&(ic->aes_ctx),
                                    RIJNDAEL_MODE_ECB, NULL);
                ctx->cipher = cipher;
                ctx->mode = mode;
                ctx->padding = padding;
                ctx->blockSize = 16;
                break;
            case CIPHER_TWOFISH:
                ctx->cipher = cipher;
                ctx->mode = mode;
                ctx->padding = padding;
                ctx->blockSize = 16;
                break;
            case CIPHER_SERPENT:
                ctx->cipher = cipher;
                ctx->mode = mode;
                ctx->padding = padding;
                ctx->blockSize = 16;
                break;
            default:
                return 2;
        }
    }
    return 0;
}

int cipher_set_key(cipherContext* ctx, uchar* key, uint keylen) {
    int k;
    internalKeyUnion* ik = NULL;
    int iterations = 1;

    /* For XTS we have a second key instance, which we need to set up. */
    if (ctx->mode == MODE_XTS) {
        iterations = 2;
        /* XTS uses two keys */
        keylen = keylen / 2;
    }
    for (k = 0; k < iterations; k++) {
        if (k == 0) {
            ik = &(ctx->internalKey);
        }
        else if (k == 1) {
            ik = &(ctx->internalKey2);
            key += keylen;
        }
        switch(ctx->cipher) {
            case CIPHER_NONE:
                break;
            case CIPHER_SERPENT:
                if (keylen > 32 || keylen < 16 || keylen % 8 != 0)
                    return 2;
                serpent_set_key(&(ik->serpent_key), key, keylen * 8);
                break;
            case CIPHER_TWOFISH:
                if (keylen > 32 || keylen < 16 || keylen % 8 != 0)
                    return 2;
                twofish_setkey(&(ik->twofish_key), key, keylen);
                break;
            case CIPHER_AES:
                if (keylen > 32 || keylen < 16 || keylen % 8 != 0)
                    return 2;
                rijndael_makeKey(&(ik->aes_keys.enc_key), DIR_ENCRYPT, 
                                 keylen * 8, (char*)key);
                rijndael_makeKey(&(ik->aes_keys.dec_key), DIR_DECRYPT, 
                                 keylen * 8, (char*)key);
                break;
            default:
                return 2;
        }
    }
    return 0;
}

/* Callback function for block en/decryption. This function is for
 * encrypting exactly one block. To be used for implementing operation modes.
 */
static void enc_dec_callback(cipherContext* ctx, uchar* msg, uint msg_len,
                             uchar* dst, uint dir, uint context) {
    internalContextUnion* ic;
    internalKeyUnion* ik = NULL;

    if (context == 1) {
        ic = &(ctx->internalContext);
        ik = &(ctx->internalKey);
    }
    else if (context == 2) {
        ic = &(ctx->internalContext2);
        ik = &(ctx->internalKey2);
    }
    else {
        return;
    }
    switch(ctx->cipher) {
        case CIPHER_NONE:
            memcpy(dst, msg, msg_len);
            return;
        case CIPHER_AES:
            if (dir == 0) /* encrypt */
                rijndael_blockEncrypt(&(ic->aes_ctx), 
                                      &(ik->aes_keys.enc_key), 
                                      msg, msg_len * 8, dst);
            else if (dir == 1)
                rijndael_blockDecrypt(&(ic->aes_ctx), 
                                      &(ik->aes_keys.dec_key), 
                                      msg, msg_len * 8, dst);
            return;
        case CIPHER_TWOFISH:
            if (dir == 0) /* encrypt */
                twofish_encrypt(&(ik->twofish_key), msg, dst);
            if (dir == 1)
                twofish_decrypt(&(ik->twofish_key), msg, dst);
            return;
        case CIPHER_SERPENT:
            if (dir == 0) /* encrypt */
                serpent_encrypt(&(ik->serpent_key), msg, dst);
            if (dir == 1)
                serpent_decrypt(&(ik->serpent_key), msg, dst);
            return;
    }
}

int cipher_encrypt(cipherContext* ctx, uchar* msg, uint msg_len, 
                   uchar* dst, uint* result) {
    switch(ctx->mode) {
        case MODE_ECB:
            enc_dec_callback(ctx, msg, msg_len, dst, 0, 1);
            *result = msg_len;
            return 0;
        case MODE_XTS:
            memcpy(dst, msg, msg_len);
            xts_encrypt_sector(dst, 
                              *((lba_type*)(ctx->mode_extra)),
                              msg_len,
                              ctx, enc_dec_callback );
            return 0;
        default:
            return 2;
    }
    return 2;
}

int cipher_decrypt(cipherContext *ctx, uchar* msg, uint msg_len, 
                   uchar* dst, uint* result) {
    switch(ctx->mode) {
        case MODE_ECB:
            enc_dec_callback(ctx, msg, msg_len, dst, 1, 1);
            *result = msg_len;
            return 0;
        case MODE_XTS:
            memcpy(dst, msg, msg_len);
            *result = xts_decrypt_sector(dst, 
                               *((lba_type*)(ctx->mode_extra)),
                               msg_len,
                               ctx, enc_dec_callback );
            return 0;
        default:
            return 2;
    }
    return 2;
}
