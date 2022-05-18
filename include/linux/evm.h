/* SPDX-License-Identifier: GPL-2.0 */
/*
 * evm.h
 *
 * Copyright (c) 2009 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 */

#ifndef _LINUX_EVM_H
#define _LINUX_EVM_H

#include <linux/integrity.h>
#include <linux/integrity_namespace.h>
#include <linux/xattr.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>

struct integrity_iint_cache;
struct integrity_namespace;

struct evm_namespace {
	unsigned long evm_ns_flags;
/* Bit numbers for above flags; use BIT() to get flag */
#define EVM_NS_ACTIVE			1
#define EVM_NS_DISABLED			2

	struct integrity_namespace *integrity_ns;
	int evm_initialized;

#define MAX_KEY_SIZE 128
	unsigned char evmkey[MAX_KEY_SIZE];
	int evmkey_len; /* always equals MAX_KEY_SIZE */;

	unsigned long evm_set_key_flags;
#define EVM_SET_KEY_BUSY 0

	int evm_hmac_attrs;

	struct mutex mutex;
	struct crypto_shash *hmac_tfm;
	struct crypto_shash *evm_tfm[HASH_ALGO__LAST];

	/* List of EVM protected security xattrs */
	struct list_head evm_config_xattrnames;

	/* EVM securityfs */
#ifdef CONFIG_EVM_ADD_XATTRS
	struct dentry *evm_xattrs;
	struct mutex xattr_list_mutex;
	int evm_xattrs_locked;
#endif
};

extern struct evm_namespace init_evm_ns;

#if defined(CONFIG_IMA_NS) && defined(CONFIG_EVM)
extern struct evm_namespace *create_evm_ns
				(struct integrity_namespace *integrity_ns);
extern void free_evm_ns(struct integrity_namespace *evm_ns);
#endif

#ifdef CONFIG_EVM
extern int evm_set_key(struct evm_namespace *ns, void *key, size_t keylen);
extern enum integrity_status evm_verifyxattr(struct evm_namespace *ns,
					     struct dentry *dentry,
					     const char *xattr_name,
					     void *xattr_value,
					     size_t xattr_value_len,
					     struct integrity_iint_cache *iint);
int evm_inode_init_security(struct inode *inode, struct inode *dir,
			    const struct qstr *qstr, struct xattr *xattrs,
			    int *xattr_count);
extern bool evm_revalidate_status(struct evm_namespace *ns,
				  const char *xattr_name);
extern int evm_protected_xattr_if_enabled(struct evm_namespace *ns,
					  const char *req_xattr_name);
extern int evm_read_protected_xattrs(struct evm_namespace *ns,
				     struct dentry *dentry, u8 *buffer,
				     int buffer_size, char type,
				     bool canonical_fmt);
#ifdef CONFIG_FS_POSIX_ACL
extern int posix_xattr_acl(const char *xattrname);
#else
static inline int posix_xattr_acl(const char *xattrname)
{
	return 0;
}
#endif
#else

static inline int evm_set_key(struct evm_namespace *ns,
			      void *key, size_t keylen)
{
	return -EOPNOTSUPP;
}

#ifdef CONFIG_INTEGRITY
static inline enum integrity_status evm_verifyxattr(
					struct evm_namespace *ns,
					struct dentry *dentry,
					const char *xattr_name,
					void *xattr_value,
					size_t xattr_value_len,
					struct integrity_iint_cache *iint)
{
	return INTEGRITY_UNKNOWN;
}
#endif

static inline int evm_inode_init_security(struct inode *inode, struct inode *dir,
					  const struct qstr *qstr,
					  struct xattr *xattrs,
					  int *xattr_count)
{
	return 0;
}

static inline bool evm_revalidate_status(struct evm_namespace *ns,
					 const char *xattr_name)
{
	return false;
}

static inline int evm_protected_xattr_if_enabled(struct evm_namespace *ns,
						 const char *req_xattr_name)
{
	return false;
}

static inline int evm_read_protected_xattrs(struct evm_namespace *ns,
					    struct dentry *dentry, u8 *buffer,
					    int buffer_size, char type,
					    bool canonical_fmt)
{
	return -EOPNOTSUPP;
}

#endif /* CONFIG_EVM */
#endif /* LINUX_EVM_H */
