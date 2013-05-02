/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <code@gregorkopf.de> wrote this file. As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return Gregor Kopf
 * ----------------------------------------------------------------------------
 */
#ifndef _COMMON_H
#define _COMMON_H

#include <stdlib.h>
#include <stdint.h>

/* FIXME: Aren't there any built-in macros for 64 bit byte ordering?! */
#define betoh64(x)     (((uint64_t)(x) << 56) | \
                        (((uint64_t)(x) << 40) & 0xff000000000000ULL) | \
                        (((uint64_t)(x) << 24) & 0xff0000000000ULL) | \
                        (((uint64_t)(x) << 8)  & 0xff00000000ULL) | \
                        (((uint64_t)(x) >> 8)  & 0xff000000ULL) | \
                        (((uint64_t)(x) >> 24) & 0xff0000ULL) | \
                        (((uint64_t)(x) >> 40) & 0xff00ULL) | \
                        ((uint64_t)(x)  >> 56))



/* Be very careful when changing these typedefs. Some parts of the
 * code may rely on the sizes of the types.
 */
typedef uint32_t uint;     /* sizeof(uint)   == 4 */
typedef uint8_t uchar;     /* sizeof(uchar)  == 1 */
typedef uint16_t ushort;   /* sizeof(ushort) == 2 */
#if defined(dword)
#else
typedef uint32_t dword;    /* sizeof(dword)  == 4 */
#endif
typedef uint64_t qword;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#define null NULL
#define arrlen(X) (sizeof(X)/sizeof(X[0]))

#endif
