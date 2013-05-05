/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _KEYFILE_H
#define _KEYFILE_H

#define KEYFILE_POOL_SIZE 64
#define KEYFILE_MAX_LEN (1024*1024*1024)

#include <inttypes.h>

uint8_t* tc_addKeyfile(int fd);
void tc_addPassword(char* password, uint8_t* pool);

#endif
