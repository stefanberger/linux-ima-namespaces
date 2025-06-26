/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * MLDSA helper functions
 *
 * Copyright (c) 2025, IBM Corporation
 */
#ifndef _CRYPTO_MLDSA_
#define _CRYPTO_MLDSA_

#include <linux/kconfig.h>

/* All OIDs are 11 bytes long */
#define MAX_MLDSA_OID_SIZE	11

#if IS_ENABLED(CONFIG_CRYPTO_MLDSA)

static inline ssize_t mldsa_oid_hash_build(unsigned char **bufp,
					   enum hash_algo hash_algo,
					   const unsigned char *digest,
					   size_t digest_size)
{
	unsigned char oid[10] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
		0x03, 0x04, 0x02};
	unsigned char *buf;
	unsigned char loid;
	size_t exp_size;

	switch (hash_algo) {
	case HASH_ALGO_SHA256:
		loid = 0x01;
		exp_size = SHA256_DIGEST_SIZE;
		break;
	case HASH_ALGO_SHA512:
		loid = 0x3;
		exp_size = SHA512_DIGEST_SIZE;
		break;
	case HASH_ALGO_SHAKE128:
		loid = 0xb;
		exp_size = 256 / 8;
		break;
	default:
		return -EBADMSG;
	}
	if (exp_size != digest_size)
		return -EBADMSG;

	buf = kmalloc(MAX_MLDSA_OID_SIZE + digest_size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memcpy(buf, oid , 10);
	buf[10] = loid;
	memcpy(&buf[11], digest, digest_size);
	*bufp = buf;

	return MAX_MLDSA_OID_SIZE + digest_size;
}

#else

static inline ssize_t mldsa_oid_hash_build(unsigned char **buf,
					   enum hash_algo,
					   unsigned char *digest,
					   size_t digest_size)
{
	return -EBADMSG;
}

#endif

#endif
