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
#include <linux/rbtree.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/security.h>
#include <linux/lsm_hooks.h>
#include "integrity.h"

struct integrity_rbtree {
	struct rb_root rb_root;
	rwlock_t rwlock;
	struct kmem_cache *cache;
};

static struct integrity_rbtree iint_tree = {
	.rb_root = RB_ROOT,
	.rwlock = __RW_LOCK_UNLOCKED(iint_tree.rwlock),
};

/* The global tree holding all inode entries; from the 'global' entries in this
 * tree linked lists are starting and connect to the iint entries referencing
 * the same inode.
 */
static struct integrity_rbtree global_tree = {
	.rb_root = RB_ROOT,
	.rwlock = __RW_LOCK_UNLOCKED(global_tree.rwlock),
};

struct dentry *integrity_dir;

/* The integrity_lists_lock must be used when *intending* to traverse any of the
 * linked lists starting in elements stored in the integrity_global_tree. Therefore,
 * the lock must be locked BEFORE finding an iint for example in the global tree.
 *
 * read-lock for read-ony traversal
 * write-lock for adding/removing nodes
 */
static DEFINE_RWLOCK(integrity_lists_lock);

/*
 * Lock order:
 * 1) integrity_lists_lock
 * 2) global_tree.rwlock
 * 3) iint_tree.rwlock
 */

/*
 * __integrity_rbtree_find - return an entry associated with an inode
 */
static struct integrity_rbtree_common *__integrity_rbtree_find(struct rb_root *rb_root,
							       struct inode *inode)
{
	struct integrity_rbtree_common *common;
	struct rb_node *n = rb_root->rb_node;

	while (n) {
		common = rb_entry(n, struct integrity_rbtree_common, rb_node);

		if (inode < common->inode)
			n = n->rb_left;
		else if (inode > common->inode)
			n = n->rb_right;
		else
			break;
	}
	if (!n)
		return NULL;

	return common;
}

/*
 * __integrity_rbtree_insert : insert the given integrity_iint_common
 *
 * @rb_root: The rb-tree to insert the node into; must hold lock on it
 * @common: The structure to insert with common->inode set to the inode
 *
 */
static void __integrity_rbtree_insert(struct rb_root *rb_root,
		                      struct integrity_rbtree_common *common)
{
	struct integrity_rbtree_common *test_common;
	struct rb_node *node, *parent = NULL;
	struct rb_node **p;

	p = &rb_root->rb_node;

	while (*p) {
		parent = *p;
		test_common = rb_entry(parent, struct integrity_rbtree_common,
				       rb_node);
		if (common->inode < test_common->inode)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	node = &common->rb_node;
	rb_link_node(node, parent, p);
	rb_insert_color(node, rb_root);
}

/*
 * integrity_iint_find - return the iint associated with an inode
 */
struct integrity_iint_cache *integrity_iint_find(struct inode *inode)
{
	struct integrity_iint_cache *iint;

	if (!IS_IMA(inode))
		return NULL;

	read_lock(&iint_tree.rwlock);
	iint = (struct integrity_iint_cache *)
			__integrity_rbtree_find(&iint_tree.rb_root, inode);
	read_unlock(&iint_tree.rwlock);

	return iint;
}

static void iint_free(struct integrity_iint_cache *iint)
{
	if (!iint)
		return;

	kfree(iint->ima_hash);
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
	kmem_cache_free(iint_tree.cache, iint);
}

static void global_free(struct integrity_global_cache *global)
{
	if (!global)
		return;

	kmem_cache_free(global_tree.cache, global);
}

/**
 * integrity_global_inode_find - find an inode in the global cache
 * @inode: pointer to the inode
 */
static struct integrity_global_cache *integrity_global_inode_find(struct inode *inode)
{
	struct integrity_global_cache *global;

	if (!IS_IMA(inode))
		return NULL;

	read_lock(&global_tree.rwlock);
	global = (struct integrity_global_cache *)
			__integrity_rbtree_find(&global_tree.rb_root, inode);
	read_unlock(&global_tree.rwlock);

	return global;
}

/**
 * integrity_global_get - find or allocate an global entry associated with an inode
 * @inode: pointer to the inode
 * @return: allocated iint
 *
 * Caller must lock i_mutex
 */
static struct integrity_global_cache *integrity_global_inode_get(struct inode *inode)
{
	struct integrity_global_cache *global;

	/*
	 * The integrity's "global_cache" is initialized at security_init(),
	 * unless it is not included in the ordered list of LSMs enabled
	 * on the boot command line.
	 */
	if (!global_tree.cache)
		panic("%s: lsm=integrity required.\n", __func__);

	global = integrity_global_inode_find(inode);
	if (global)
		return global;

	global = kmem_cache_alloc(global_tree.cache, GFP_NOFS);
	if (!global)
		return NULL;

	global->common.inode = inode;
	global->common.rb_root = &global_tree.rb_root;
	global->common.rb_tree_lock = &global_tree.rwlock;
	global->common.global = global;
	INIT_LIST_HEAD(&global->common.node);
	inode->i_flags |= S_IMA;

	write_lock(&global_tree.rwlock);

	__integrity_rbtree_insert(&global_tree.rb_root, &global->common);

	write_unlock(&global_tree.rwlock);

	return global;
}

/**
 * integrity_global_inode_free - called on security_inode_free
 * @inode: pointer to the inode
 *
 * Remove the inode from the global cache and remove it from all rb-trees it
 * is connected to via linked list connectint iint structures.
 */
void integrity_global_inode_free(struct inode *inode)
{
	struct integrity_global_cache *global;
	struct integrity_iint_cache *iint, *tmp;

	if (!IS_IMA(inode))
		return;

	write_lock(&integrity_lists_lock);
	write_lock(&global_tree.rwlock);

	global = (struct integrity_global_cache *)
			__integrity_rbtree_find(&global_tree.rb_root, inode);
	if (!global)
		goto exit;
	rb_erase(&global->common.rb_node, &global_tree.rb_root);

	list_for_each_entry_safe(iint, tmp, &global->common.node, common.node) {
		/* remove iint from the tree it is on */
		// Q: What ensures that this node is still on its tree?
		// A: integrity_inode_free will be removed -> this is the only function removing it
		write_lock(iint->common.rb_tree_lock);
		rb_erase(&iint->common.rb_node, iint->common.rb_root);
		write_unlock(iint->common.rb_tree_lock);

		/* remove iint from the list (protected by integrity_lists_lock) */
		list_del(&iint->common.node);

		iint_free(iint);
	}

exit:
	write_unlock(&global_tree.rwlock);
	write_unlock(&integrity_lists_lock);

	global_free(global);
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
	struct integrity_global_cache *global;

	/*
	 * The integrity's "iint_cache" is initialized at security_init(),
	 * unless it is not included in the ordered list of LSMs enabled
	 * on the boot command line.
	 */
	if (!iint_tree.cache)
		panic("%s: lsm=integrity required.\n", __func__);

	iint = integrity_iint_find(inode);
	if (iint)
		return iint;

	iint = kmem_cache_alloc(iint_tree.cache, GFP_NOFS);
	if (!iint)
		return NULL;

	global = integrity_global_inode_get(inode);
	if (!global) {
		iint_free(iint);
		return NULL;
	}

	write_lock(&integrity_lists_lock);
	write_lock(&iint_tree.rwlock);

	iint->common.inode = inode;
	iint->common.rb_root = &iint_tree.rb_root;
	iint->common.rb_tree_lock = &iint_tree.rwlock;
	iint->common.global = global;
	list_add(&iint->common.node, &global->common.node);
	inode->i_flags |= S_IMA;

	__integrity_rbtree_insert(&iint_tree.rb_root, &iint->common);

	write_unlock(&iint_tree.rwlock);
	write_unlock(&integrity_lists_lock);

	return iint;
}

/**
 * integrity_rbtree_delete - delete an entire rbtree and remove all its iints
 *			     from the list they are on, possibly deleting the
 *			     entry from the global tree as well.
 * @i_rbtree: An integrity_rbtree with root, lock, and memory cache
 */
void integrity_rbtree_delete(struct integrity_rbtree *i_rbtree)
{
	struct integrity_iint_cache *iint, *tmp;

	write_lock(&integrity_lists_lock);
	write_lock(&global_tree.rwlock);
	write_lock(&i_rbtree->rwlock);

	rbtree_postorder_for_each_entry_safe(iint, tmp,
					     &i_rbtree->rb_root, common.rb_node) {
		struct integrity_global_cache *global;
		/* no need to remove node from rbtree; kmem_cache_destroy will delete tree */

		/* remove iint from the list (protected by integrity_list_lock) */
		list_del(&iint->common.node);

		/* if this was the last node on this list we delete the global
		 * entry (protected by global_tree.rwlock) */
		global = iint->common.global;
		if (list_empty(&global->common.node)) {
			rb_erase(&global->common.rb_node, &global_tree.rb_root);
			global_free(global);
		}

		iint_free(iint);
	}

	write_unlock(&i_rbtree->rwlock);
	write_unlock(&global_tree.rwlock);
	write_unlock(&integrity_lists_lock);

	kmem_cache_destroy(i_rbtree->cache);
}

static void iint_init_once(void *foo)
{
	struct integrity_iint_cache *iint = (struct integrity_iint_cache *) foo;

	memset(iint, 0, sizeof(*iint));
	iint->ima_file_status = INTEGRITY_UNKNOWN;
	iint->ima_mmap_status = INTEGRITY_UNKNOWN;
	iint->ima_bprm_status = INTEGRITY_UNKNOWN;
	iint->ima_read_status = INTEGRITY_UNKNOWN;
	iint->ima_creds_status = INTEGRITY_UNKNOWN;
	iint->evm_status = INTEGRITY_UNKNOWN;
	mutex_init(&iint->mutex);
}

static void global_init_once(void *foo)
{
	struct integrity_global_cache *global = (struct integrity_global_cache *) foo;

	memset(global, 0, sizeof(*global));
}

static int __init integrity_caches_init(void)
{
	iint_tree.cache =
	    kmem_cache_create("iint_cache", sizeof(struct integrity_iint_cache),
			      0, SLAB_PANIC, iint_init_once);
	global_tree.cache =
	    kmem_cache_create("global_cache", sizeof(struct integrity_global_cache),
			      0, SLAB_PANIC, global_init_once);
	return 0;
}
DEFINE_LSM(integrity) = {
	.name = "integrity",
	.init = integrity_caches_init,
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
