/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for SHA-3 algorithms
 */
#ifndef __CRYPTO_SHA3_H__
#define __CRYPTO_SHA3_H__

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)

#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)

#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)

#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3_state {
	u64		st[25];
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	u8		buf[SHA3_224_BLOCK_SIZE];
};

struct shash_desc;

int crypto_sha3_init(struct shash_desc *desc);
int crypto_sha3_update(struct shash_desc *desc, const u8 *data,
		       unsigned int len);
int crypto_sha3_final(struct shash_desc *desc, u8 *out);


#define SHAKE128_DIGEST_SIZE	(128 / 8)
#define SHAKE128_BLOCK_SIZE	(200 - 2 * SHAKE128_DIGEST_SIZE)

#define SHAKE256_DIGEST_SIZE	(256 / 8)
#define SHAKE256_BLOCK_SIZE	(200 - 2 * SHAKE256_DIGEST_SIZE)

#define SHAKE128_RATE		((1600 - 256) / 8)
#define SHAKE256_RATE		((1600 - 512) / 8)

struct shake_state {
	u64		st[25];
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	u8		buf[SHAKE128_BLOCK_SIZE];
	bool		finalized;
	bool		permute;
	unsigned int	ridx;
};

#include "crypto/hash.h"
static_assert(sizeof(struct shake_state) <= HASH_MAX_DESCSIZE);

#endif
