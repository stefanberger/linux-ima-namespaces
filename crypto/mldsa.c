// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 IBM Corporation
 */

#include <linux/module.h>
#include <crypto/internal/sig.h>
#include <crypto/sha2.h>
#include <crypto/sig.h>

#include "mldsa_crypto.h"

struct dil_ctx {
	unsigned int exp_key_size;
	unsigned int pub_key_size;
	unsigned char pub_key[DIL_MLDSA_87_PUB_BYTES];
};

#define MLCA_ALGORITHM_SIG_MLDSA_44_OID "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x11"
#define MLCA_ALGORITHM_SIG_MLDSA_65_OID "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x12"
#define MLCA_ALGORITHM_SIG_MLDSA_87_OID "\x06\x09" "\x60\x86\x48\x01\x65\x03\x04\x03\x13"

/*
 * Verify an ECDSA signature.
 */
static int mldsa_verify_sig(struct crypto_sig *tfm,
			const void *src, unsigned int slen,
			const void *digest, unsigned int dlen)
{
	int ret;
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);
	unsigned char oid[11];

	printk(KERN_INFO "%s @ %u   slen=%d dlen=%d\n", __func__, __LINE__, slen, dlen);
	switch (ctx->pub_key_size) {
	case DIL_MLDSA_44_PUB_BYTES:
		memcpy(oid, MLCA_ALGORITHM_SIG_MLDSA_44_OID, 11);
		break;
	case DIL_MLDSA_65_PUB_BYTES:
		memcpy(oid, MLCA_ALGORITHM_SIG_MLDSA_65_OID, 11);
		break;
	case DIL_MLDSA_87_PUB_BYTES:
		memcpy(oid, MLCA_ALGORITHM_SIG_MLDSA_87_OID, 11);
		break;
	}
	ret = mlca_verify(src, slen, digest, dlen, ctx->pub_key, ctx->pub_key_size,
	                  oid, 11);
	printk(KERN_INFO "%s @ %u   ret=%d\n", __func__, __LINE__, ret);
	return ret == 1 ? 0 : -EKEYREJECTED;
}

static int mldsa_ecc_ctx_init(struct dil_ctx *ctx, unsigned int pub_key_size)
{
	ctx->exp_key_size = pub_key_size;
	return 0;
}

static void mldsa_ctx_deinit(struct dil_ctx *ctx)
{
	ctx->pub_key_size = 0;
}

static int mldsa_ctx_reset(struct dil_ctx *ctx)
{
	mldsa_ctx_deinit(ctx);
	return mldsa_ecc_ctx_init(ctx, ctx->exp_key_size);
}

/*
 * Set the public MLDSA key.
 */
static int mldsa_set_pub_key(struct crypto_sig *tfm, const void *key,
			     unsigned int keylen)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	if (keylen != ctx->exp_key_size)
		return -EKEYREJECTED;

	ret = mldsa_ctx_reset(ctx);
	if (ret < 0)
		return ret;

	memcpy(ctx->pub_key, key, keylen);
	ctx->pub_key_size = keylen;

	return ret;
}

static void mldsa_exit_tfm(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	mldsa_ctx_deinit(ctx);
}

static unsigned int mldsa_key_size(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return ctx->pub_key_size;
}

static unsigned int mldsa_digest_size(struct crypto_sig *tfm)
{
	printk(KERN_INFO "%s @ %u\n", __func__, __LINE__);
	return SHA512_DIGEST_SIZE;
}

static int mldsa_44_init_tfm(struct crypto_sig *tfm)
{
	struct dil_ctx *ctx = crypto_sig_ctx(tfm);

	return mldsa_ecc_ctx_init(ctx, DIL_MLDSA_44_PUB_BYTES);
}

static struct sig_alg mldsa_44 = {
	.verify = mldsa_verify_sig,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
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

	return mldsa_ecc_ctx_init(ctx, DIL_MLDSA_65_PUB_BYTES);
}

static struct sig_alg mldsa_65 = {
	.verify = mldsa_verify_sig,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
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

	return mldsa_ecc_ctx_init(ctx, DIL_MLDSA_87_PUB_BYTES);
}

static struct sig_alg mldsa_87 = {
	.verify = mldsa_verify_sig,
	.set_pub_key = mldsa_set_pub_key,
	.key_size = mldsa_key_size,
	.digest_size = mldsa_digest_size,
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
	return ret;
}

static void __exit mldsa_exit(void)
{
	crypto_unregister_sig(&mldsa_87);
	crypto_unregister_sig(&mldsa_65);
	crypto_unregister_sig(&mldsa_44);
}

subsys_initcall(mldsa_init);
module_exit(mldsa_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stefan Berger <stefanb@linux.ibm.com>");
MODULE_DESCRIPTION("MLDSA generic algorithm");
MODULE_ALIAS_CRYPTO("mldsa-44");
MODULE_ALIAS_CRYPTO("mldsa-65");
MODULE_ALIAS_CRYPTO("mldsa-87");
MODULE_ALIAS_CRYPTO("mldsa-generic");
