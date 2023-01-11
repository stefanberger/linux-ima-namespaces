// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2005-2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * File: evm_crypto.c
 *	 Using root's kernel master key (kmk), calculate the HMAC
 */

#define pr_fmt(fmt) "EVM: "fmt

#include <linux/export.h>
#include <linux/crypto.h>
#include <linux/xattr.h>
#include <linux/evm.h>
#include <keys/encrypted-type.h>
#include "evm.h"

#define EVMKEY "evm-key"

static const char evm_hmac[] = "hmac(sha1)";

#ifdef CONFIG_IMA_NS
void evm_ns_free_crypto(struct evm_namespace *ns)
{
	size_t i;

	if (ns->hmac_tfm)
		crypto_free_shash(ns->hmac_tfm);

	for (i = 0; i < ARRAY_SIZE(ns->evm_tfm); i++) {
		if (ns->evm_tfm[i])
			crypto_free_shash(ns->evm_tfm[i]);
	}
}
#endif

/**
 * evm_set_key() - set EVM HMAC key from the kernel
 * @ns: The EVM namespace to set the key on
 * @key: pointer to a buffer with the key data
 * @keylen: length of the key data
 *
 * This function allows setting the EVM HMAC key from the kernel
 * without using the "encrypted" key subsystem keys. It can be used
 * by the crypto HW kernel module which has its own way of managing
 * keys.
 *
 * key length should be between 32 and 128 bytes long
 */
int evm_set_key(struct evm_namespace *ns, void *key, size_t keylen)
{
	int rc;

	rc = -EBUSY;
	if (test_and_set_bit(EVM_SET_KEY_BUSY, &ns->evm_set_key_flags))
		goto busy;
	rc = -EINVAL;
	if (keylen > MAX_KEY_SIZE)
		goto inval;
	memcpy(ns->evmkey, key, keylen);
	ns->evm_initialized |= EVM_INIT_HMAC;
	pr_info("key initialized\n");
	return 0;
inval:
	clear_bit(EVM_SET_KEY_BUSY, &ns->evm_set_key_flags);
busy:
	pr_err("key initialization failed\n");
	return rc;
}
EXPORT_SYMBOL_GPL(evm_set_key);

static struct shash_desc *init_desc(struct evm_namespace *ns,
				    char type, uint8_t hash_algo)
{
	long rc;
	const char *algo;
	struct crypto_shash **tfm, *tmp_tfm;
	struct shash_desc *desc;

	if (type == EVM_XATTR_HMAC) {
		if (!(ns->evm_initialized & EVM_INIT_HMAC)) {
			pr_err_once("HMAC key is not set\n");
			return ERR_PTR(-ENOKEY);
		}
		tfm = &ns->hmac_tfm;
		algo = evm_hmac;
	} else {
		if (hash_algo >= HASH_ALGO__LAST)
			return ERR_PTR(-EINVAL);

		tfm = &ns->evm_tfm[hash_algo];
		algo = hash_algo_name[hash_algo];
	}

	if (*tfm)
		goto alloc;
	mutex_lock(&ns->mutex);
	if (*tfm)
		goto unlock;

	tmp_tfm = crypto_alloc_shash(algo, 0, CRYPTO_NOLOAD);
	if (IS_ERR(tmp_tfm)) {
		pr_err("Can not allocate %s (reason: %ld)\n", algo,
		       PTR_ERR(tmp_tfm));
		mutex_unlock(&ns->mutex);
		return ERR_CAST(tmp_tfm);
	}
	if (type == EVM_XATTR_HMAC) {
		rc = crypto_shash_setkey(tmp_tfm, ns->evmkey, ns->evmkey_len);
		if (rc) {
			mutex_unlock(&ns->mutex);
			return ERR_PTR(rc);
		}
	}
	*tfm = tmp_tfm;
unlock:
	mutex_unlock(&ns->mutex);
alloc:
	desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(*tfm),
			GFP_KERNEL);
	if (!desc)
		return ERR_PTR(-ENOMEM);

	desc->tfm = *tfm;

	rc = crypto_shash_init(desc);
	if (rc) {
		kfree(desc);
		return ERR_PTR(rc);
	}
	return desc;
}

/* Protect against 'cutting & pasting' security.evm xattr, include inode
 * specific info.
 *
 * (Additional directory/file metadata needs to be added for more complete
 * protection.)
 */
static void hmac_add_misc(struct evm_namespace *ns,
			  struct shash_desc *desc, struct inode *inode,
			  char type, char *digest)
{
	struct h_misc {
		unsigned long ino;
		__u32 generation;
		uid_t uid;
		gid_t gid;
		umode_t mode;
	} hmac_misc;

	memset(&hmac_misc, 0, sizeof(hmac_misc));
	/* Don't include the inode or generation number in portable
	 * signatures
	 */
	if (type != EVM_XATTR_PORTABLE_DIGSIG) {
		hmac_misc.ino = inode->i_ino;
		hmac_misc.generation = inode->i_generation;
	}
	/* The hmac uid and gid must be encoded in the initial user
	 * namespace (not the filesystems user namespace) as encoding
	 * them in the filesystems user namespace allows an attack
	 * where first they are written in an unprivileged fuse mount
	 * of a filesystem and then the system is tricked to mount the
	 * filesystem for real on next boot and trust it because
	 * everything is signed.
	 */
	hmac_misc.uid = from_kuid(current_user_ns(), inode->i_uid);
	hmac_misc.gid = from_kgid(current_user_ns(), inode->i_gid);
	hmac_misc.mode = inode->i_mode;
	crypto_shash_update(desc, (const u8 *)&hmac_misc, sizeof(hmac_misc));
	if ((ns->evm_hmac_attrs & EVM_ATTR_FSUUID) &&
	    type != EVM_XATTR_PORTABLE_DIGSIG)
		crypto_shash_update(desc, (u8 *)&inode->i_sb->s_uuid, UUID_SIZE);
	crypto_shash_final(desc, digest);

	pr_debug("hmac_misc: (%zu) [%*phN]\n", sizeof(struct h_misc),
		 (int)sizeof(struct h_misc), &hmac_misc);
}

/*
 * Dump large security xattr values as a continuous ascii hexademical string.
 * (pr_debug is limited to 64 bytes.)
 */
static void dump_security_xattr_l(const char *prefix, const void *src,
				  size_t count)
{
#if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
	char *asciihex, *p;

	p = asciihex = kmalloc(count * 2 + 1, GFP_KERNEL);
	if (!asciihex)
		return;

	p = bin2hex(p, src, count);
	*p = 0;
	pr_debug("%s: (%zu) %.*s\n", prefix, count, (int)count * 2, asciihex);
	kfree(asciihex);
#endif
}

static void dump_security_xattr(const char *name, const char *value,
				size_t value_len)
{
	if (value_len < 64)
		pr_debug("%s: (%zu) [%*phN]\n", name, value_len,
			 (int)value_len, value);
	else
		dump_security_xattr_l(name, value, value_len);
}

/*
 * Calculate the HMAC value across the set of protected security xattrs.
 *
 * Instead of retrieving the requested xattr, for performance, calculate
 * the hmac using the requested xattr value. Don't alloc/free memory for
 * each xattr, but attempt to re-use the previously allocated memory.
 */
static int evm_calc_hmac_or_hash(struct evm_namespace *ns,
				 struct dentry *dentry,
				 const char *req_xattr_name,
				 const char *req_xattr_value,
				 size_t req_xattr_value_len,
				 uint8_t type, struct evm_digest *data)
{
	struct inode *inode = d_backing_inode(dentry);
	struct xattr_list *xattr;
	struct shash_desc *desc;
	size_t xattr_size = 0;
	char *xattr_value = NULL;
	int error;
	int size, user_space_size;
	bool ima_present = false;

	if (!(inode->i_opflags & IOP_XATTR) ||
	    inode->i_sb->s_user_ns != &init_user_ns)
		return -EOPNOTSUPP;

	desc = init_desc(ns, type, data->hdr.algo);
	if (IS_ERR(desc))
		return PTR_ERR(desc);

	data->hdr.length = crypto_shash_digestsize(desc->tfm);

	error = -ENODATA;
	list_for_each_entry_lockless(xattr, &ns->evm_config_xattrnames, list) {
		bool is_ima = false;

		if (strcmp(xattr->name, XATTR_NAME_IMA) == 0)
			is_ima = true;

		/*
		 * Skip non-enabled xattrs for locally calculated
		 * signatures/HMACs.
		 */
		if (type != EVM_XATTR_PORTABLE_DIGSIG && !xattr->enabled)
			continue;

		if ((req_xattr_name && req_xattr_value)
		    && !strcmp(xattr->name, req_xattr_name)) {
			error = 0;
			crypto_shash_update(desc, (const u8 *)req_xattr_value,
					     req_xattr_value_len);
			if (is_ima)
				ima_present = true;

			dump_security_xattr(req_xattr_name,
					    req_xattr_value,
					    req_xattr_value_len);
			continue;
		}
		size = vfs_getxattr_alloc(&nop_mnt_idmap, dentry, xattr->name,
					  &xattr_value, xattr_size, GFP_NOFS);
		if (size == -ENOMEM) {
			error = -ENOMEM;
			goto out;
		}
		if (size < 0)
			continue;

		user_space_size = vfs_getxattr(&nop_mnt_idmap, dentry,
					       xattr->name, NULL, 0);
		if (user_space_size != size)
			pr_debug("file %s: xattr %s size mismatch (kernel: %d, user: %d)\n",
				 dentry->d_name.name, xattr->name, size,
				 user_space_size);
		error = 0;
		xattr_size = size;
		crypto_shash_update(desc, (const u8 *)xattr_value, xattr_size);
		if (is_ima)
			ima_present = true;

		dump_security_xattr(xattr->name, xattr_value, xattr_size);
	}
	hmac_add_misc(ns, desc, inode, type, data->digest);

	/* Portable EVM signatures must include an IMA hash */
	if (type == EVM_XATTR_PORTABLE_DIGSIG && !ima_present)
		error = -EPERM;
out:
	kfree(xattr_value);
	kfree(desc);
	return error;
}

int evm_calc_hmac(struct evm_namespace *ns, struct dentry *dentry,
		  const char *req_xattr_name,
		  const char *req_xattr_value, size_t req_xattr_value_len,
		  struct evm_digest *data)
{
	return evm_calc_hmac_or_hash(ns, dentry, req_xattr_name,
				     req_xattr_value, req_xattr_value_len,
				     EVM_XATTR_HMAC, data);
}

int evm_calc_hash(struct evm_namespace *ns, struct dentry *dentry,
		  const char *req_xattr_name,
		  const char *req_xattr_value, size_t req_xattr_value_len,
		  char type, struct evm_digest *data)
{
	return evm_calc_hmac_or_hash(ns, dentry, req_xattr_name,
				     req_xattr_value, req_xattr_value_len,
				     type, data);
}

static int evm_is_immutable(struct dentry *dentry, struct inode *inode)
{
	const struct evm_ima_xattr_data *xattr_data = NULL;
	struct integrity_iint_cache *iint;
	int rc = 0;

	iint = integrity_iint_find(inode);
	if (iint && (iint->flags & EVM_IMMUTABLE_DIGSIG))
		return 1;

	/* Do this the hard way */
	rc = vfs_getxattr_alloc(&nop_mnt_idmap, dentry, XATTR_NAME_EVM,
				(char **)&xattr_data, 0, GFP_NOFS);
	if (rc <= 0) {
		if (rc == -ENODATA)
			rc = 0;
		goto out;
	}
	if (xattr_data->type == EVM_XATTR_PORTABLE_DIGSIG)
		rc = 1;
	else
		rc = 0;

out:
	kfree(xattr_data);
	return rc;
}


/*
 * Calculate the hmac and update security.evm xattr
 *
 * Expects to be called with i_mutex locked.
 */
int evm_update_evmxattr(struct evm_namespace *ns, struct dentry *dentry,
			const char *xattr_name,
			const char *xattr_value, size_t xattr_value_len)
{
	struct inode *inode = d_backing_inode(dentry);
	struct evm_digest data;
	int rc = 0;

	/*
	 * Don't permit any transformation of the EVM xattr if the signature
	 * is of an immutable type
	 */
	rc = evm_is_immutable(dentry, inode);
	if (rc < 0)
		return rc;
	if (rc)
		return -EPERM;

	data.hdr.algo = HASH_ALGO_SHA1;
	rc = evm_calc_hmac(ns, dentry, xattr_name, xattr_value,
			   xattr_value_len, &data);
	if (rc == 0) {
		data.hdr.xattr.sha1.type = EVM_XATTR_HMAC;
		rc = __vfs_setxattr_noperm(&nop_mnt_idmap, dentry,
					   XATTR_NAME_EVM,
					   &data.hdr.xattr.data[1],
					   SHA1_DIGEST_SIZE + 1, 0);
	} else if (rc == -ENODATA && (inode->i_opflags & IOP_XATTR)) {
		rc = __vfs_removexattr(&nop_mnt_idmap, dentry, XATTR_NAME_EVM);
	}
	return rc;
}

int evm_init_hmac(struct evm_namespace *ns, struct inode *inode,
		  const struct xattr *lsm_xattr, char *hmac_val)
{
	struct shash_desc *desc;

	desc = init_desc(ns, EVM_XATTR_HMAC, HASH_ALGO_SHA1);
	if (IS_ERR(desc)) {
		pr_info("init_desc failed\n");
		return PTR_ERR(desc);
	}

	crypto_shash_update(desc, lsm_xattr->value, lsm_xattr->value_len);
	hmac_add_misc(ns, desc, inode, EVM_XATTR_HMAC, hmac_val);
	kfree(desc);
	return 0;
}

/*
 * Get the key from the TPM for the SHA1-HMAC
 */
int evm_init_key(struct evm_namespace *ns)
{
	struct key *evm_key;
	struct encrypted_key_payload *ekp;
	int rc;

	evm_key = request_key(&key_type_encrypted, EVMKEY, NULL);
	if (IS_ERR(evm_key))
		return -ENOENT;

	down_read(&evm_key->sem);
	ekp = evm_key->payload.data[0];

	rc = evm_set_key(ns, ekp->decrypted_data, ekp->decrypted_datalen);

	/* burn the original key contents */
	memset(ekp->decrypted_data, 0, ekp->decrypted_datalen);
	up_read(&evm_key->sem);
	key_put(evm_key);
	return rc;
}
