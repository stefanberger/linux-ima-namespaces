// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 IBM Corporation
 */

#include <linux/module.h>
#include <crypto/internal/sig.h>
#include <crypto/sha2.h>
#include <crypto/sha3.h>
#include <crypto/sig.h>

#include "mldsa.h"
#include "mldsa_crypto.h"

/* ML-DSA's crypto needs shake256/128 */
struct crypto_shash *crypto_mldsa_shake256;
struct crypto_shash *crypto_mldsa_shake128;

struct mldsa_ctx {
	unsigned int exp_key_size;
	unsigned int pub_key_size;
	unsigned char pub_key[MLDSA_87_PUB_BYTES];
};

#define DOMSEP_PURE	0
#define DOMSEP_PREHASH	1

#define MLDSA_HASH_OID_SIZE	11

static const unsigned char mldsa_oid_prefix[10] = {
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02
};

static const struct prehash {
	char *name;
	unsigned int id;
	size_t hashlen;
} prehashes[] = {
	{ "sha256", 1, SHA256_DIGEST_SIZE },
	{ "sha384", 2, SHA384_DIGEST_SIZE },
	{ "sha512", 3, SHA512_DIGEST_SIZE },
	{ "sha224", 4, SHA224_DIGEST_SIZE },
	{ "sha512-224", 5, SHA224_DIGEST_SIZE },
	{ "sha512-256", 6, SHA256_DIGEST_SIZE },
	{ "sha3-224", 7, SHA3_224_DIGEST_SIZE },
	{ "sha3-256", 8, SHA3_256_DIGEST_SIZE },
	{ "sha3-384", 9, SHA3_384_DIGEST_SIZE },
	{ "sha3-512", 10, SHA3_512_DIGEST_SIZE },
	{ "shake128" , 11, SHAKE128_DIGEST_SIZE * 2 },
	{ "shake256" , 12, SHAKE256_DIGEST_SIZE * 2 },
};

/*
 * Verify an MLDSA signature
 *
 * @tfm: poineter to crypto_sig
 * @src: signature
 * @slen: length of signature
 * @digest: a prehash digest or NULL
 * @dlen: length of the digest
 * @prehash_algo: name of the prehash
 * @msg: plain message; alternative to @digest
 * @mlen: message length
 * @ctx: context string
 * @clen: length of context string; must be <= 255
 */
static int mldsa_verify(struct crypto_sig *tfm,
			const void *src, unsigned int slen,
			const void *digest, unsigned int dlen,
			const char *prehash_algo,
			const void *msg, unsigned int mlen,
			const void *ctxt, unsigned int clen)
{
	unsigned char encoded[MLDSA_HASH_OID_SIZE + SHA512_DIGEST_SIZE];
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);
	unsigned char hashid;
	unsigned char domsep;
	size_t explen, i;
	int ret;

	if (unlikely(ctx->pub_key_size == 0))
		return -EKEYREJECTED;

	if (!msg) {
		/*
		 * The input expects a valid digest and prehash_alg describing
		 * what the digest represents.
		 */
		if (!prehash_algo)
			return -EBADMSG;

		explen = 0;
		for (i = 0; i < ARRAY_SIZE(prehashes); i++) {
			if (!strcmp(prehashes[i].name, prehash_algo)) {
				hashid = prehashes[i].id;
				explen = prehashes[i].hashlen;
				break;
			}
		}
		if (!explen || explen != dlen)
			return -EBADMSG;

		memcpy(encoded, mldsa_oid_prefix, 10);
		encoded[10] = hashid;
		//printk(KERN_INFO "hashid: %d\n", hashid);
		memcpy(&encoded[MLDSA_HASH_OID_SIZE], digest, dlen);
		domsep = DOMSEP_PREHASH;
		ret = mldsa_verify_internal(src, slen, encoded,
					    MLDSA_HASH_OID_SIZE + dlen,
					    ctx->pub_key,
					    ctx->pub_key_size,
					    &domsep, sizeof(domsep),
					    ctxt, clen, NULL);
	} else {
		domsep = DOMSEP_PURE;
		ret = mldsa_verify_internal(src, slen, msg, mlen,
					    ctx->pub_key,
					    ctx->pub_key_size,
					    &domsep, sizeof(domsep),
					    ctxt, clen, NULL);
	}
	if (ret < 0)
		return ret;

	return ret == 1 ? 0 : -EKEYREJECTED;
}

static int mldsa_ctx_init(struct mldsa_ctx *ctx, unsigned int exp_key_size)
{
	ctx->exp_key_size = exp_key_size;

	return 0;
}

/*
 * Set the public MLDSA key.
 */
static int mldsa_set_pub_key(struct crypto_sig *tfm, const void *key,
			     unsigned int keylen)
{
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);

	if (keylen != ctx->exp_key_size)
		return -EKEYREJECTED;

	memcpy(ctx->pub_key, key, keylen);
	ctx->pub_key_size = keylen;

	return 0;
}

static void mldsa_exit_tfm(struct crypto_sig *tfm)
{
}

static unsigned int mldsa_key_size(struct crypto_sig *tfm)
{
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);

	return ctx->pub_key_size * 8;
}

static unsigned int mldsa_digest_size(struct crypto_sig *tfm)
{
	return SHAKE256_DIGEST_SIZE;
}

static unsigned int mldsa_max_sig_size(struct crypto_sig *tfm)
{
	return MLDSA_MAX_SIG_SIZE;
}

#include "mldsa_kat.h"
#include "nist_mldsa_kat.h"

static int mldsa_44_init_tfm(struct crypto_sig *tfm)
{
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ret = mldsa_ctx_init(ctx, MLDSA_44_PUB_BYTES);

	mldsa44_kat(tfm);
	nist_mldsa44_kat(tfm);

	return ret;
}

static struct sig_alg mldsa_44 = {
	.verify2 = mldsa_verify,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
	.max_size = mldsa_max_sig_size,
	.init = mldsa_44_init_tfm,
	.exit = mldsa_exit_tfm,
	.base = {
		.cra_name = "mldsa-44",
		.cra_driver_name = "mldsa-44-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct mldsa_ctx),
	},
};

static int mldsa_65_init_tfm(struct crypto_sig *tfm)
{
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ret = mldsa_ctx_init(ctx, MLDSA_65_PUB_BYTES);

	nist_mldsa65_kat(tfm);

	return ret;
}

static struct sig_alg mldsa_65 = {
	.verify2 = mldsa_verify,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
	.max_size = mldsa_max_sig_size,
	.init = mldsa_65_init_tfm,
	.exit = mldsa_exit_tfm,
	.base = {
		.cra_name = "mldsa-65",
		.cra_driver_name = "mldsa-65-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct mldsa_ctx),
	},
};

static int mldsa_87_init_tfm(struct crypto_sig *tfm)
{
	struct mldsa_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ret = mldsa_ctx_init(ctx, MLDSA_87_PUB_BYTES);

	nist_mldsa87_kat(tfm);

	return ret;
}

static struct sig_alg mldsa_87 = {
	.verify2 = mldsa_verify,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
	.max_size = mldsa_max_sig_size,
	.init = mldsa_87_init_tfm,
	.exit = mldsa_exit_tfm,
	.base = {
		.cra_name = "mldsa-87",
		.cra_driver_name = "mldsa-87-generic",
		.cra_priority = 100,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct mldsa_ctx),
	},
};

static int __init mldsa_init(void)
{
	int ret;

	crypto_mldsa_shake256 = crypto_alloc_shash("shake256", 0, 0);
	if (IS_ERR(crypto_mldsa_shake256))
		return PTR_ERR(crypto_mldsa_shake256);

	crypto_mldsa_shake128 = crypto_alloc_shash("shake128", 0, 0);
	if (IS_ERR(crypto_mldsa_shake128)) {
		ret = PTR_ERR(crypto_mldsa_shake128);
		goto shake128_error;
	}

	ret = crypto_register_sig(&mldsa_44);
	if (ret)
		goto mldsa_44_error;

	ret = crypto_register_sig(&mldsa_65);
	if (ret)
		goto mldsa_65_error;

	ret = crypto_register_sig(&mldsa_87);
	if (ret)
		goto mldsa_87_error;

	return 0;

mldsa_87_error:
	crypto_unregister_sig(&mldsa_65);

mldsa_65_error:
	crypto_unregister_sig(&mldsa_44);

mldsa_44_error:
	crypto_free_shash(crypto_mldsa_shake128);

shake128_error:
	crypto_free_shash(crypto_mldsa_shake256);

	return ret;
}

static void __exit mldsa_exit(void)
{
	crypto_free_shash(crypto_mldsa_shake128);
	crypto_free_shash(crypto_mldsa_shake256);
	crypto_unregister_sig(&mldsa_87);
	crypto_unregister_sig(&mldsa_65);
	crypto_unregister_sig(&mldsa_44);
}

subsys_initcall_sync(mldsa_init);
module_exit(mldsa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stefan Berger <stefanb@linux.ibm.com>");
MODULE_DESCRIPTION("MLDSA generic algorithm");
MODULE_ALIAS_CRYPTO("mldsa-44");
MODULE_ALIAS_CRYPTO("mldsa-65");
MODULE_ALIAS_CRYPTO("mldsa-87");
MODULE_ALIAS_CRYPTO("mldsa-generic");
