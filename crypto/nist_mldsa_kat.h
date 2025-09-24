
#include "crypto/hash.h"

struct mldsa_tc
{
	unsigned int tgid;
	unsigned int tcid;
	char *prehash;
	char *hashalg;
	bool valid;
	size_t pk_size;
	unsigned char *pk;
	size_t msg_size;
	unsigned char *msg;
	size_t ctx_size;
	unsigned char *ctx;
	size_t mu_size;
	unsigned char *mu;
	size_t sig_size;
	unsigned char *sig;
};

#include "nist_mldsa_kats.h"

static int do_shash(const char *name,
                    unsigned char *result, size_t *result_size,
                    unsigned char *msg, size_t msg_size)
{
	struct crypto_shash *tfm;
	int ret;

	tfm = crypto_alloc_shash(name, 0, 0);
	if (IS_ERR(tfm)) {
		printk(KERN_INFO "shash allocation failed\n");
		return  PTR_ERR(tfm);
	}
	*result_size = crypto_shash_digestsize(tfm);
	if (strncmp(name, "shake", 5) == 0) {
		SHASH_DESC_ON_STACK(desc, tfm);

		*result_size *= 2;
		desc->tfm = tfm;
		crypto_shash_init(desc);
		crypto_shash_update(desc, msg, msg_size);
		crypto_shash_squeeze(desc,
				     result, *result_size, true);
	} else {
		ret = crypto_shash_tfm_digest(tfm, msg, msg_size, result);
	}
	crypto_free_shash(tfm);
	return ret;
}

static void nist_mldsa_kat(struct crypto_sig *tfm,
                           const struct mldsa_tc ml_dsa_tcs[],
                           size_t num_tcs,
                           const char *typ)
{
	unsigned char hash[64];
	size_t hash_size;
        size_t i;
        int ret;

        printk(KERN_INFO "Begin NIST ML-DSA-%s tests\n", typ);

	for (i = 0; i < num_tcs; i++) {
		ret = mldsa_set_pub_key(tfm,
					ml_dsa_tcs[i].pk,
					ml_dsa_tcs[i].pk_size);
		if (ret)
			printk(KERN_INFO "ERROR: Could not set public key!\n");
		if (strcmp(ml_dsa_tcs[i].hashalg, "none") == 0 &&
		    strcmp(ml_dsa_tcs[i].prehash, "none") == 0) {
		    	ret = mldsa_verify_internal(ml_dsa_tcs[i].sig,
						    ml_dsa_tcs[i].sig_size,
						    ml_dsa_tcs[i].msg,
						    ml_dsa_tcs[i].msg_size,
						    ml_dsa_tcs[i].pk,
						    ml_dsa_tcs[i].pk_size,
						    NULL, 0, NULL, 0,
						    ml_dsa_tcs[i].mu_size
						       ? ml_dsa_tcs[i].mu
						       : NULL);
			/* adjust return code */
			if (ret == 0)
				ret = -EKEYREJECTED;
			if (ret == 1)
				ret = 0;
		} else if (strcmp(ml_dsa_tcs[i].hashalg, "none") != 0) {
			ret = do_shash(ml_dsa_tcs[i].hashalg,
			               hash, &hash_size,
			               ml_dsa_tcs[i].msg,
			               ml_dsa_tcs[i].msg_size);
			if (ret)
				printk(KERN_INFO "Error: Could not calculate hash '%s': %d\n",
				       ml_dsa_tcs[i].hashalg, ret);
			ret = mldsa_verify(tfm,
					   ml_dsa_tcs[i].sig,
					   ml_dsa_tcs[i].sig_size,
					   hash, hash_size, ml_dsa_tcs[i].hashalg,
					   NULL, 0,
					   ml_dsa_tcs[i].ctx_size ? ml_dsa_tcs[i].ctx : NULL,
					   ml_dsa_tcs[i].ctx_size);
		} else {
			ret = mldsa_verify(tfm,
					   ml_dsa_tcs[i].sig,
					   ml_dsa_tcs[i].sig_size,
					   NULL, 0, NULL,
					   ml_dsa_tcs[i].msg,
					   ml_dsa_tcs[i].msg_size,
					   ml_dsa_tcs[i].ctx,
					   ml_dsa_tcs[i].ctx_size);
		}
		if (ml_dsa_tcs[i].valid) {
			if (ret != 0)
				printk(KERN_INFO "ERROR: Could not verify signature!: %d (%u/%u)\n", ret,
				       ml_dsa_tcs[i].tgid, ml_dsa_tcs[i].tcid);
		} else {
			if (ret == 0)
				printk(KERN_INFO "ERROR: Could verify signature!: %d\n", ret);
		}
	}
	printk(KERN_INFO "End of NIST ML-DSA-%s tests\n", typ);
}

static void nist_mldsa44_kat(struct crypto_sig *tfm)
{
	nist_mldsa_kat(tfm, ml_dsa_44_tcs, ARRAY_SIZE(ml_dsa_44_tcs), "44");
}
static void nist_mldsa65_kat(struct crypto_sig *tfm)
{
	nist_mldsa_kat(tfm, ml_dsa_65_tcs, ARRAY_SIZE(ml_dsa_65_tcs), "65");
}
static void nist_mldsa87_kat(struct crypto_sig *tfm)
{
	nist_mldsa_kat(tfm, ml_dsa_87_tcs, ARRAY_SIZE(ml_dsa_87_tcs), "87");
}
