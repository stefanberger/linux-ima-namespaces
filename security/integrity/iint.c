// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2008 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * File: integrity_iint.c
 *	- implements the integrity hooks: integrity_inode_alloc,
 *	  integrity_inode_free
 *	- cache integrity information associated with an inode
 *	  using a rbtree tree.
 */
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include <linux/ima.h>
#include "integrity.h"

static struct kmem_cache *iint_cache __ro_after_init;

struct dentry *integrity_dir;

/*
 * integrity_iint_find - return the iint associated with an inode
 */
struct integrity_iint_cache *integrity_iint_find(struct inode *inode)
{
	if (!IS_IMA(inode))
		return NULL;

	return integrity_inode_get_iint(inode);
}

#define IMA_MAX_NESTING (FILESYSTEM_MAX_STACK_DEPTH+1)

/*
 * It is not clear that IMA should be nested at all, but as long is it measures
 * files both on overlayfs and on underlying fs, we need to annotate the iint
 * mutex to avoid lockdep false positives related to IMA + overlayfs.
 * See ovl_lockdep_annotate_inode_mutex_key() for more details.
 */
static inline void iint_lockdep_annotate(struct integrity_iint_cache *iint,
					 struct inode *inode)
{
#ifdef CONFIG_LOCKDEP
	static struct lock_class_key iint_mutex_key[IMA_MAX_NESTING];

	int depth = inode->i_sb->s_stack_depth;

	if (WARN_ON_ONCE(depth < 0 || depth >= IMA_MAX_NESTING))
		depth = 0;

	lockdep_set_class(&iint->mutex, &iint_mutex_key[depth]);
#endif
}

static void iint_init_always(struct integrity_iint_cache *iint,
			     struct inode *inode)
{
	iint->ima_hash = NULL;
	iint->version = 0;
	iint->flags = 0UL;
	iint->atomic_flags = 0UL;
	iint->ima_file_status = INTEGRITY_UNKNOWN;
	iint->ima_mmap_status = INTEGRITY_UNKNOWN;
	iint->ima_bprm_status = INTEGRITY_UNKNOWN;
	iint->ima_read_status = INTEGRITY_UNKNOWN;
	iint->ima_creds_status = INTEGRITY_UNKNOWN;
	iint->evm_status = INTEGRITY_UNKNOWN;
	iint->measured_pcrs = 0;
	mutex_init(&iint->mutex);
	iint_lockdep_annotate(iint, inode);
	rwlock_init(&iint->ns_list_lock);
	INIT_LIST_HEAD(&iint->ns_list);
}

static void iint_free(struct integrity_iint_cache *iint)
{
	kfree(iint->ima_hash);
	mutex_destroy(&iint->mutex);
	kmem_cache_free(iint_cache, iint);
}

/**
 * integrity_inode_get - find or allocate an iint associated with an inode
 * @inode: pointer to the inode
 * @return: allocated iint
 *
 * Caller must lock i_mutex
 */
struct integrity_iint_cache *integrity_inode_get(struct inode *inode)
{
	struct integrity_iint_cache *iint;

	iint = integrity_iint_find(inode);
	if (iint)
		return iint;

	iint = kmem_cache_alloc(iint_cache, GFP_NOFS);
	if (!iint)
		return NULL;

	iint_init_always(iint, inode);

	iint->inode = inode;
	inode->i_flags |= S_IMA;
	integrity_inode_set_iint(inode, iint);

	return iint;
}

/**
 * integrity_inode_free - called on security_inode_free
 * @inode: pointer to the inode
 *
 * Free the integrity information(iint) associated with an inode.
 */
static void integrity_inode_free(struct inode *inode)
{
	struct integrity_iint_cache *iint;

	if (!IS_IMA(inode))
		return;

	iint = integrity_iint_find(inode);
	integrity_inode_set_iint(inode, NULL);

	ima_free_ns_status_list(iint);

	iint_free(iint);
}

static void iint_init_once(void *foo)
{
	struct integrity_iint_cache *iint = (struct integrity_iint_cache *) foo;

	memset(iint, 0, sizeof(*iint));
}

static struct security_hook_list integrity_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_free_security, integrity_inode_free),
#ifdef CONFIG_INTEGRITY_ASYMMETRIC_KEYS
	LSM_HOOK_INIT(kernel_module_request, integrity_kernel_module_request),
#endif
};

/*
 * Perform the initialization of the 'integrity', 'ima' and 'evm' LSMs to
 * ensure that the management of integrity metadata is working at the time
 * IMA and EVM hooks are registered to the LSM infrastructure, and to keep
 * the original ordering of IMA and EVM functions as when they were hardcoded.
 */
static int __init integrity_lsm_init(void)
{
	const struct lsm_id *lsmid;

	iint_cache =
	    kmem_cache_create("iint_cache", sizeof(struct integrity_iint_cache),
			      0, SLAB_PANIC, iint_init_once);
	/*
	 * Obtain either the IMA or EVM LSM ID to register integrity-specific
	 * hooks under that LSM, since there is no LSM ID assigned to the
	 * 'integrity' LSM.
	 */
	lsmid = ima_get_lsm_id();
	if (!lsmid)
		lsmid = evm_get_lsm_id();
	/* No point in continuing, since both IMA and EVM are disabled. */
	if (!lsmid)
		return 0;

	security_add_hooks(integrity_hooks, ARRAY_SIZE(integrity_hooks), lsmid);
	init_ima_lsm();
	init_evm_lsm();
	return 0;
}

struct lsm_blob_sizes integrity_blob_sizes __ro_after_init = {
	.lbs_inode = sizeof(struct integrity_iint_cache *),
};

/*
 * Keep it until IMA and EVM can use disjoint integrity metadata, and their
 * initialization order can be swapped without change in their behavior.
 */
DEFINE_LSM(integrity) = {
	.name = "integrity",
	.init = integrity_lsm_init,
	.order = LSM_ORDER_LAST,
	.blobs = &integrity_blob_sizes,
};

/*
 * integrity_kernel_read - read data from the file
 *
 * This is a function for reading file content instead of kernel_read().
 * It does not perform locking checks to ensure it cannot be blocked.
 * It does not perform security checks because it is irrelevant for IMA.
 *
 */
int integrity_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count)
{
	return __kernel_read(file, addr, count, &offset);
}

/*
 * integrity_load_keys - load integrity keys hook
 *
 * Hooks is called from init/main.c:kernel_init_freeable()
 * when rootfs is ready
 */
void __init integrity_load_keys(void)
{
	ima_load_x509();

	if (!IS_ENABLED(CONFIG_IMA_LOAD_X509))
		evm_load_x509();
}

static int __init integrity_fs_init(void)
{
	integrity_dir = securityfs_create_dir("integrity", NULL);
	if (IS_ERR(integrity_dir)) {
		int ret = PTR_ERR(integrity_dir);

		if (ret != -ENODEV)
			pr_err("Unable to create integrity sysfs dir: %d\n",
			       ret);
		integrity_dir = NULL;
		return ret;
	}

	return 0;
}

late_initcall(integrity_fs_init)
