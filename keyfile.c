/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */

#include <string.h>
#include <unistd.h>
#include "keyfile.h"
#include "hash.h"

uint8_t* tc_addKeyfile(int fd) {
    static uint8_t pool[KEYFILE_POOL_SIZE] = {0};
    size_t cnt;
    size_t cursor = 0;
    hash_ctx h;
    uint8_t c;
    /* XXX This only works for crc32 as "hash" */
    uint8_t hval[4];

    hash_init(&h, HASH_INSECURE_CRC32);
    for (cnt = 0; cnt < KEYFILE_MAX_LEN; cnt++) {
        /* Return on EOF */
        if (read(fd, &c, 1) != 1)
            return pool;
        hash_add(&h, &c, 1);
        /* XXX This only works for crc32 as "hash" */
        hval[0] = h.internalContext.crc32 >> 24;
        hval[1] = (h.internalContext.crc32 >> 16) & 0xff;
        hval[2] = (h.internalContext.crc32 >> 8) & 0xff;
        hval[3] = (h.internalContext.crc32) & 0xff;

        for (size_t i = 0; i < sizeof(hval); i++, cursor++) {
            if (cursor >= KEYFILE_POOL_SIZE)
                cursor = 0;
            pool[cursor] += hval[i];
        }
    }
    return pool;
}

/* Adds the password to the pool *in place* */
void tc_addPassword(char* password, uint8_t* pool) {
    for (size_t i = 0; i < strlen(password); i++) {
        pool[i] += password[i];
    }
}
