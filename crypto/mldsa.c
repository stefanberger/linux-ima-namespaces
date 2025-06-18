// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 IBM Corporation
 */

#include <linux/module.h>
#include <crypto/internal/sig.h>
#include <crypto/sha3.h>
#include <crypto/sig.h>

#include "mldsa.h"
#include "mldsa_crypto.h"

/* ML-DSA's crypto needs shake256/128 */
struct crypto_shash *crypto_mldsa_shake256;
struct crypto_shash *crypto_mldsa_shake128;

struct dil_ctx {
	unsigned int exp_key_size;
	unsigned int pub_key_size;
	unsigned char pub_key[DIL_MLDSA_87_PUB_BYTES];
};

/*
 * Verify an MLDSA signature.
 */
static int mldsa_verify(struct crypto_sig *tfm, const void *src,
			unsigned int slen, const void *digest,
			unsigned int dlen)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	if (unlikely(ctx->pub_key_size) == 0)
		return -EKEYREJECTED;

	ret = mldsa_verify_internal(src, slen, digest, dlen, ctx->pub_key,
				    ctx->pub_key_size);

	return ret == 1 ? 0 : -EKEYREJECTED;
}

static int mldsa_ctx_init(struct dil_ctx *ctx, unsigned int exp_key_size)
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
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

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
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return ctx->pub_key_size * 8;
}

static unsigned int mldsa_digest_size(struct crypto_sig *tfm)
{
	return SHAKE256_DIGEST_SIZE;
}

static unsigned int mldsa_max_sig_size(struct crypto_sig *tfm)
{
	return DIL_MLDSA_MAX_SIG_SIZE;
}

static int mldsa_44_init_tfm(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return mldsa_ctx_init(ctx, DIL_MLDSA_44_PUB_BYTES);
}

static struct sig_alg mldsa_44 = {
	.verify = mldsa_verify,
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
		.cra_ctxsize = sizeof(struct dil_ctx),
	},
};

static int mldsa_65_init_tfm(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return mldsa_ctx_init(ctx, DIL_MLDSA_65_PUB_BYTES);
}

static struct sig_alg mldsa_65 = {
	.verify = mldsa_verify,
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
		.cra_ctxsize = sizeof(struct dil_ctx),
	},
};

static int mldsa_87_init_tfm(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return mldsa_ctx_init(ctx, DIL_MLDSA_87_PUB_BYTES);
}

static struct sig_alg mldsa_87 = {
	.verify = mldsa_verify,
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
		.cra_ctxsize = sizeof(struct dil_ctx),
	},
};

static int __init mldsa_init(void)
{
	int ret;

	crypto_mldsa_shake256 = crypto_alloc_shash("shake256", 0, 0);
	if (IS_ERR(crypto_mldsa_shake256)) {
		return PTR_ERR(crypto_mldsa_shake256);
	}

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
