/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2005-2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 * Kylene Hall <kjhall@us.ibm.com>
 *
 * File: evm.h
 */

#ifndef __INTEGRITY_EVM_H
#define __INTEGRITY_EVM_H

#include <linux/xattr.h>
#include <linux/security.h>

#include "../integrity.h"

#define EVM_INIT_HMAC	0x0001
#define EVM_INIT_X509	0x0002
#define EVM_ALLOW_METADATA_WRITES	0x0004
#define EVM_SETUP_COMPLETE 0x80000000 /* userland has signaled key load */

#define EVM_KEY_MASK (EVM_INIT_HMAC | EVM_INIT_X509)
#define EVM_INIT_MASK (EVM_INIT_HMAC | EVM_INIT_X509 | EVM_SETUP_COMPLETE | \
		       EVM_ALLOW_METADATA_WRITES)

struct xattr_list {
	struct list_head list;
	char *name;
	bool enabled;
};

extern int evm_initialized;

#define EVM_ATTR_FSUUID		0x0001

extern int evm_hmac_attrs;

/* List of EVM protected security xattrs */
extern struct list_head evm_config_xattrnames;

struct evm_digest {
	struct ima_digest_data hdr;
	char digest[IMA_MAX_DIGEST_SIZE];
} __packed;

static inline struct evm_namespace *current_evm_ns(void)
{
	return current_integrity_ns()->evm_ns;
}

int evm_protected_xattr(const char *req_xattr_name);

int evm_init_key(struct evm_namespace *ns);
int evm_update_evmxattr(struct dentry *dentry,
			const char *req_xattr_name,
			const char *req_xattr_value,
			size_t req_xattr_value_len);
int evm_calc_hmac(struct dentry *dentry, const char *req_xattr_name,
		  const char *req_xattr_value,
		  size_t req_xattr_value_len, struct evm_digest *data);
int evm_calc_hash(struct dentry *dentry, const char *req_xattr_name,
		  const char *req_xattr_value,
		  size_t req_xattr_value_len, char type,
		  struct evm_digest *data);
int evm_init_hmac(struct inode *inode, const struct xattr *xattrs,
		  char *hmac_val);
int evm_init_secfs(struct evm_namespace *ns);
int __init evm_init_ns(void);
int evm_init_namespace(struct evm_namespace *ns,
		       struct integrity_namespace *integrity_ns);

static inline
struct evm_namespace *evm_ns_from_file(const struct file *filp)
{
	return file_sb_user_ns(filp)->integrity_ns->evm_ns;
}


#endif
