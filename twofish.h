/* This code is based on Twofish for GPG by Matthew Skala. As far as
 * I'm concerned, the Beerware license (revision 42) shall apply to my
 * changes.
 */

/* Twofish for GPG
 * By Matthew Skala <mskala@ansuz.sooke.bc.ca>, July 26, 1998
 * 256-bit key length added March 20, 1999
 * Some modifications to reduce the text size by Werner Koch, April, 1998
 *
 * The original author has disclaimed all copyright interest in this
 * code and thus putting it in the public domain.
 *
 * This code is a "clean room" implementation, written from the paper
 * _Twofish: A 128-Bit Block Cipher_ by Bruce Schneier, John Kelsey,
 * Doug Whiting, David Wagner, Chris Hall, and Niels Ferguson, available
 * through http://www.counterpane.com/twofish.html
 *
 * For background information on multiplication in finite fields, used for
 * the matrix operations in the key schedule, see the book _Contemporary
 * Abstract Algebra_ by Joseph A. Gallian, especially chapter 22 in the
 * Third Edition.
 *
 * Only the 128- and 256-bit key sizes are supported.  This code is intended
 * for GNU C on a 32-bit system, but it should work almost anywhere.  Loops
 * are unrolled, precomputation tables are used, etc., for maximum speed at
 * some cost in memory consumption. */

#ifndef _TWOFISH_H
#define _TWOFISH_H

#include "types.h"

/* Structure for an expanded Twofish key.  s contains the key-dependent
 * S-boxes composed with the MDS matrix; w contains the eight "whitening"
 * subkeys, K[0] through K[7].	k holds the remaining, "round" subkeys.  Note
 * that k[i] corresponds to what the Twofish paper calls K[i+8]. */
typedef struct {
   uint32_t s[4][256], w[8], k[32];
} TWOFISH_context;

typedef TWOFISH_context tf_key;

int twofish_setkey (TWOFISH_context *ctx, const uint8_t *key, unsigned int keylen);
int twofish_encrypt (const TWOFISH_context *ctx, uint8_t *out, const uint8_t *in);
int twofish_decrypt (const TWOFISH_context *ctx, uint8_t *out, const uint8_t *in);

#endif
