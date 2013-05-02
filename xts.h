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
*/

#ifndef _XEX_H
#define _XEX_H


#if defined(__cplusplus)
extern "C"
{
#endif

/* define if the logical block address needs a 64-bit value */
#define LONG_LBA

#include "cipher.h"

typedef uint64_t lba_type;

int xts_encrypt_sector( uchar sector[], lba_type sector_address, 
                               unsigned int sector_len, cipherContext* ctx,
                               enc_dec_cb cb );

int xts_decrypt_sector( uchar sector[], lba_type sector_address, 
                               unsigned int sector_len, cipherContext* ctx,
                               enc_dec_cb cb );

#if defined(__cplusplus)
}
#endif

#endif
