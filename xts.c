/*
 ---------------------------------------------------------------------------
 Copyright (c) 1998-2007, Brian Gladman, Worcester, UK. All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software is allowed (with or without
 changes) provided that:

  1. source code distributions include the above copyright notice, this
     list of conditions and the following disclaimer;

  2. binary distributions include the above copyright notice, this list
     of conditions and the following disclaimer in their documentation;

  3. the name of the copyright holder is not used to endorse products
     built using this software without specific written permission.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 20/12/2007

 My thanks to both Doug Whiting and Olaf Pors for their much appreciated
 assistance in debugging and testing this code.
*/

#include "xts_mode_hdr.h"
#include "xts.h"

#if defined(__cplusplus)
extern "C"
{
#endif

UNIT_TYPEDEF(buf_unit, UNIT_BITS);
/* TODO: Hard coding 16 bytes block size doesn't seem to be a good idea.
 * That should be changed depending on the cipher used. */
BUFR_TYPEDEF(buf_type, UNIT_BITS, 16);

void gf_mulx(void *x)
{
#if UNIT_BITS == 8

    uint_8t i = 16, t = ((uint_8t*)x)[15];
    while(--i)
        ((uint_8t*)x)[i] = (((uint_8t*)x)[i] << 1) | (((uint_8t*)x)[i - 1] & 0x80 ? 1 : 0);
    ((uint_8t*)x)[0] = (((uint_8t*)x)[0] << 1) ^ (t & 0x80 ? 0x87 : 0x00);

#elif PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN

#  if UNIT_BITS == 64

#   define GF_MASK  li_64(8000000000000000) 
#   define GF_XOR   li_64(0000000000000087) 
    uint_64t _tt = ((UPTR_CAST(x,64)[1] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,64)[1] = (UPTR_CAST(x,64)[1] << 1) | (UPTR_CAST(x,64)[0] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,64)[0] = (UPTR_CAST(x,64)[0] << 1) ^ _tt;

#  else /* UNIT_BITS == 32 */

#   define GF_MASK  li_32(80000000) 
#   define GF_XOR   li_32(00000087) 
    uint_32t _tt = ((UPTR_CAST(x,32)[3] & GF_MASK) ? GF_XOR : 0);;
    UPTR_CAST(x,32)[3] = (UPTR_CAST(x,32)[3] << 1) | (UPTR_CAST(x,32)[2] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[2] = (UPTR_CAST(x,32)[2] << 1) | (UPTR_CAST(x,32)[1] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[1] = (UPTR_CAST(x,32)[1] << 1) | (UPTR_CAST(x,32)[0] & GF_MASK ? 1 : 0);
    UPTR_CAST(x,32)[0] = (UPTR_CAST(x,32)[0] << 1) ^ _tt;

#  endif

#else /* PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN */

#  if UNIT_BITS == 64

#   define MASK_01  li_64(0101010101010101)
#   define GF_MASK  li_64(0000000000000080) 
#   define GF_XOR   li_64(8700000000000000) 
    uint_64t _tt = ((UPTR_CAST(x,64)[1] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,64)[1] =  ((UPTR_CAST(x,64)[1] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,64)[1] >> 15) | (UPTR_CAST(x,64)[0] << 49)) & MASK_01);
    UPTR_CAST(x,64)[0] = (((UPTR_CAST(x,64)[0] << 1) & ~MASK_01) 
        |  ((UPTR_CAST(x,64)[0] >> 15) & MASK_01)) ^ _tt;

#  else /* UNIT_BITS == 32 */

#   define MASK_01  li_32(01010101)
#   define GF_MASK  li_32(00000080) 
#   define GF_XOR   li_32(87000000) 
    uint_32t _tt = ((UPTR_CAST(x,32)[3] & GF_MASK) ? GF_XOR : 0);
    UPTR_CAST(x,32)[3] =  ((UPTR_CAST(x,32)[3] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[3] >> 15) | (UPTR_CAST(x,32)[2] << 17)) & MASK_01);
    UPTR_CAST(x,32)[2] =  ((UPTR_CAST(x,32)[2] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[2] >> 15) | (UPTR_CAST(x,32)[1] << 17)) & MASK_01);
    UPTR_CAST(x,32)[1] =  ((UPTR_CAST(x,32)[1] << 1) & ~MASK_01) 
        | (((UPTR_CAST(x,32)[1] >> 15) |   (UPTR_CAST(x,32)[0] << 17)) & MASK_01);
    UPTR_CAST(x,32)[0] = (((UPTR_CAST(x,32)[0] << 1) & ~MASK_01) 
        |  ((UPTR_CAST(x,32)[0] >> 15) & MASK_01)) ^ _tt;

#  endif

#endif
}


/* sector contains the actual data, sector_address is the number of the sector
 * (from 0 on), sector_len the length of a sector. a sector might contain
 * many block lengths. */
int xts_encrypt_sector( uchar sector[],  lba_type sector_address, 
                               unsigned int sector_len, cipherContext* ctx,
                               enc_dec_cb cb )
{   
    buf_type hh;
    uint_8t *pos = sector, *hi = sector + sector_len;
    
    xor_function f_ptr = (!ALIGN_OFFSET(sector, UNIT_BITS >> 3) ? xor_block_aligned : xor_block );

    if( sector_len < ctx->blockSize )
        return EXIT_FAILURE;

#if defined( LONG_LBA )
    *UPTR_CAST(hh, 64) = sector_address;
    memset(UPTR_CAST(hh, 8) + 8, 0, 8);
    uint_64t_to_le(*UPTR_CAST(hh, 64));
#else
    *UPTR_CAST(hh, 32) = sector_address;
    memset(UPTR_CAST(hh, 8) + 4, 0, 12);
    uint_32t_to_le(*UPTR_CAST(hh, 32));
#endif

    /* 0 = enc, 2 => second context set (tweak) */
    cb(ctx, UPTR_CAST(hh, 8), ctx->blockSize, UPTR_CAST(hh, 8), 0, 2); 

    /* Actual encryption */
    while(pos + ctx->blockSize <= hi)
    {
        f_ptr(pos, pos, hh);
        cb(ctx, pos, ctx->blockSize, pos, 0, 1);
        f_ptr(pos, pos, hh);
        pos += ctx->blockSize;
        gf_mulx(hh);
    }

    /* Padding */
    if(pos < hi)
    {
        uint_8t *tp = pos - ctx->blockSize;
        while(pos < hi)
        {
            uint_8t tt = *(pos - ctx->blockSize);
            *(pos - ctx->blockSize) = *pos;
            *pos++ = tt;
        }
        f_ptr(tp, tp, hh);
        cb(ctx, tp, ctx->blockSize, tp, 0, 1);
        f_ptr(tp, tp, hh);
    }
    return EXIT_SUCCESS;
}

int xts_decrypt_sector( uchar sector[], lba_type sector_address, 
                               unsigned int sector_len, cipherContext* ctx,
                               enc_dec_cb cb)
{   
    buf_type hh, hh2;
    uint_8t *pos = sector, *hi = sector + sector_len;

    xor_function f_ptr = (!ALIGN_OFFSET(sector, UNIT_BITS >> 3) ? xor_block_aligned : xor_block );

    if( sector_len < ctx->blockSize )
        return EXIT_FAILURE;

#if defined( LONG_LBA )
    *UPTR_CAST(hh, 64) = sector_address;
    memset(UPTR_CAST(hh, 8) + 8, 0, 8);
    uint_64t_to_le(*UPTR_CAST(hh, 64));
#else
    *UPTR_CAST(hh, 32) = sector_address;
    memset(UPTR_CAST(hh, 8) + 4, 0, 12);
    uint_32t_to_le(*UPTR_CAST(hh, 32));
#endif

    /* 1 == decrypt */
    cb(ctx, UPTR_CAST(hh, 8), ctx->blockSize, UPTR_CAST(hh, 8), 0, 2);

    while(pos + ctx->blockSize <= hi)
    {
        if(hi - pos > ctx->blockSize && hi - pos < 2 * ctx->blockSize)
        {
            memcpy(hh2, hh, ctx->blockSize);
            gf_mulx(hh);
        }
        f_ptr(pos, pos, hh);
        cb(ctx, pos, ctx->blockSize, pos, 1, 1);
        f_ptr(pos, pos, hh);
        pos += ctx->blockSize;
        gf_mulx(hh);
    }

    if(pos < hi)
    {
        uint_8t *tp = pos - ctx->blockSize;
        while(pos < hi)
        {
            uint_8t tt = *(pos - ctx->blockSize);
            *(pos - ctx->blockSize) = *pos;
            *pos++ = tt;
        }
        f_ptr(tp, tp, hh2);
        cb(ctx, tp, ctx->blockSize, tp, 1, 1);
        f_ptr(tp, tp, hh2);
    }

    return EXIT_SUCCESS;
}

#if defined(__cplusplus)
}
#endif
