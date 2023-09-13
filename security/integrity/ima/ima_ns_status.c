// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2021 IBM Corporation
 * Author:
 *  Yuqiong Sun <suny@us.ibm.com>
 *  Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include <linux/user_namespace.h>
#include <linux/ima.h>

#include "ima.h"

/*
 * An ns_status must be on a per-namespace list and on a per-iint list.
 *
 * Locking order for ns_status:
 * 1) ns->ns_status_list_lock : Lock the ns' list
 * 2) iint->ns_list_lock      : Lock the iint's list
 *
 * An ns_status can be freed either by walking the namespace linked list
 * (namespace deletion) or by walking the linked list of ns_status connected
 * to an iint (inode/iint deletion). There are two functions that implement
 * each one of the cases:
 * - ima_ns_free_ns_status_list(struct ima_namespace *ns)
 * - ima_free_ns_status_list(struct integrity_iint_cache *iint)
 * To avoid concurrent freeing of the same ns_status, the two freeing functions
 * cannot be run concurrently but each functions can be run by multiple threads
 * since no two threads will free the same inode/iint and no two threads will
 * free the same namespace. Grouping threads like this ensures that:
 * - while walking the namespace list: all ns_status will be on their list and
 *                                     the iint will still exist
 * - while walking the iint list     : all ns_status will be on their namespace
 *                                     list
 */
enum lk_group {
	GRP_IINT_STATUS_LIST = 0,
	GRP_NS_STATUS_LIST
};

static atomic_t lg_ctr[2] = {
	ATOMIC_INIT(0),
	ATOMIC_INIT(0)
};

static DEFINE_SPINLOCK(lg_ctr_lock);

static struct wait_queue_head lg_wq[2] = {
	__WAIT_QUEUE_HEAD_INITIALIZER(lg_wq[0]),
	__WAIT_QUEUE_HEAD_INITIALIZER(lg_wq[1])
};

static atomic_t ns_list_waiters = ATOMIC_INIT(0);

static atomic_t passes = ATOMIC_INIT(0);
static atomic_t sleeps = ATOMIC_INIT(0);
static atomic_t long_sleeps = ATOMIC_INIT(0);
static atomic_t reports = ATOMIC_INIT(0);

/*
 * Any number of concurrent threads may free ns_status's in either one of the
 * groups but the groups must not run concurrently. The GRP_NS_STATUS_LIST
 * group yields to waiters in the GRP_IINT_STATUS_LIST group since namespace
 * deletion has more time.
 */
static void lock_group(enum lk_group group, bool do_count)
{
	unsigned long flags;
	bool done = false;
	int announced = 0;
	bool slept = false;

	while (1) {
		spin_lock_irqsave(&lg_ctr_lock, flags);

		switch (group) {
		case GRP_IINT_STATUS_LIST:
			if (atomic_read(&lg_ctr[GRP_NS_STATUS_LIST]) == 0) {
				if (announced)
					atomic_dec(&ns_list_waiters);
				done = true;
				atomic_inc(&lg_ctr[GRP_IINT_STATUS_LIST]);
			} else {
				if (!announced) {
					atomic_inc(&ns_list_waiters);
					announced = 1;
				}
			}
			break;
		case GRP_NS_STATUS_LIST:
			if (atomic_read(&lg_ctr[GRP_IINT_STATUS_LIST]) == 0 &&
			    atomic_read(&ns_list_waiters) == 0) {
				done = true;
				atomic_inc(&lg_ctr[GRP_NS_STATUS_LIST]);
			}
			break;
		}

		spin_unlock_irqrestore(&lg_ctr_lock, flags);

		if (do_count) {
			if (done && !slept) {
				atomic_inc(&passes);
			}
			if (done) {
				atomic_inc(&reports);
				if ((atomic_read(&reports) % 10000) == 0)
					printk(KERN_INFO "sleeps: %u long sleeps: %u passes: %u\n",
					       atomic_read(&sleeps),
					       atomic_read(&long_sleeps),
					       atomic_read(&passes));
			}
		}

		if (done)
			break;

		/* wait until opposite group is done */
		switch (group) {
		case GRP_IINT_STATUS_LIST:
			if (do_count) {
				if (!slept) {
					slept = true;
					atomic_inc(&sleeps);
				} else {
					atomic_inc(&long_sleeps);
				}
			}
			wait_event_interruptible
			    (lg_wq[GRP_IINT_STATUS_LIST],
			     atomic_read(&lg_ctr[GRP_NS_STATUS_LIST]) == 0);
			break;
		case GRP_NS_STATUS_LIST:
			wait_event_interruptible
			    (lg_wq[GRP_NS_STATUS_LIST],
			     atomic_read(&lg_ctr[GRP_IINT_STATUS_LIST]) == 0 &&
			     atomic_read(&ns_list_waiters) == 0);
			break;
		}
	}
}

static void unlock_group(enum lk_group group)
{
	switch (group) {
	case GRP_IINT_STATUS_LIST:
		if (atomic_dec_and_test(&lg_ctr[GRP_IINT_STATUS_LIST]))
			wake_up_interruptible_all(&lg_wq[GRP_NS_STATUS_LIST]);
		break;
	case GRP_NS_STATUS_LIST:
		if (atomic_dec_and_test(&lg_ctr[GRP_NS_STATUS_LIST]))
			wake_up_interruptible_all(&lg_wq[GRP_IINT_STATUS_LIST]);
		break;
	}
}

static void ns_status_free(struct ima_namespace *ns,
			   struct ns_status *ns_status)
{
	pr_debug("FREE ns_status: %p\n", ns_status);
	kfree(ns_status->ima_hash);
	ns_status->ima_hash = NULL;

	kmem_cache_free(ns->ns_status_cache, ns_status);
}

/*
 * ima_ns_free_ns_status_list - free all items on the ns_status_list and take
 *                              each one off the list; yield to iint ns_list
 *                              free'ers
 *
 * This function is called when an ima_namespace is freed.
 * All ns_status's connected to the ima_namespace list are taken off both lists
 * and the ns_status is freed.
 */
void ima_ns_free_ns_status_list(struct ima_namespace *ns)
{
	struct ns_status *ns_status, *next;
	unsigned int ctr;
	bool restart;

	do {
		ctr = 0;
		restart = false;

		lock_group(GRP_NS_STATUS_LIST, false);
		write_lock(&ns->ns_status_list_lock);

		list_for_each_entry_safe(ns_status, next, &ns->ns_status_list,
					 ns_node) {
			list_del(&ns_status->ns_node);

			write_lock(&ns_status->iint->ns_list_lock);

			BUG_ON(list_empty(&ns_status->ns_next));
			list_del_init(&ns_status->ns_next);

			write_unlock(&ns_status->iint->ns_list_lock);

			ns_status_free(ns, ns_status);
			ctr++;

			/*
			 * After some progress yield to any waiting ns_list
			 * free'ers.
			 */
			if (atomic_read(&ns_list_waiters) > 0 && ctr >= 5) {
				restart = true;
				break;
			}
		}

		write_unlock(&ns->ns_status_list_lock);
		unlock_group(GRP_NS_STATUS_LIST);

		if (restart)
			schedule();
	} while (restart);

	kmem_cache_destroy(ns->ns_status_cache);
}

/*
 * ima_free_ns_status_list: free the list of ns_status items; take each one off
 *                          the iint and the namespace list
 */
void ima_free_ns_status_list(struct integrity_iint_cache *iint)
{
	struct list_head *head = &iint->ns_list;
	struct ns_status *ns_status;

	lock_group(GRP_IINT_STATUS_LIST, true);

	while (1) {
		write_lock(&iint->ns_list_lock);
		ns_status = list_first_entry_or_null(head, struct ns_status,
						     ns_next);
		if (ns_status)
			list_del_init(&ns_status->ns_next);
		write_unlock(&iint->ns_list_lock);

		if (!ns_status)
			break;

		write_lock(&ns_status->ns->ns_status_list_lock);

		list_del(&ns_status->ns_node);

		write_unlock(&ns_status->ns->ns_status_list_lock);

		ns_status_free(ns_status->ns, ns_status);
	}

	unlock_group(GRP_IINT_STATUS_LIST);
}

/* Find an ns_status by walking the iint's linked list of ns_status'es */
struct ns_status *ima_find_ns_status(struct integrity_iint_cache *iint,
				     struct ima_namespace *ns)
{
	struct ns_status *ns_status = NULL;
	bool found;

	read_lock(&iint->ns_list_lock);

	list_for_each_entry(ns_status, &iint->ns_list, ns_next) {
		found = ns_status->ns == ns;
		if (found)
			break;
	}

	if (!found)
		ns_status = NULL;

	read_unlock(&iint->ns_list_lock);

	return ns_status;
}

struct ns_status *ima_get_ns_status(struct ima_namespace *ns,
				    struct inode *inode,
				    struct integrity_iint_cache *iint)
{
	struct ns_status *ns_status;
	bool get_new = true;

	/*
	 * Prevent finding the status via the list (inode/iint deletion)
	 * since we may modify it here
	 */
	lock_group(GRP_NS_STATUS_LIST, false);

	ns_status = ima_find_ns_status(iint, ns);
	if (ns_status) {
		BUG_ON(ns_status->iint != iint);
		if (inode->i_ino == ns_status->i_ino &&
		    inode->i_generation == ns_status->i_generation) {
			goto unlock;
		} else {
			/* Reuse of ns_status is possible but need reset */
			get_new = false;
		}
	}

	if (get_new) {
		ns_status = kmem_cache_alloc(ns->ns_status_cache, GFP_NOFS);
		if (!ns_status) {
			ns_status = ERR_PTR(-ENOMEM);
			goto unlock;
		}
	}

	write_lock(&ns->ns_status_list_lock);

	if (get_new) {
		pr_debug("NEW  ns_status: %p\n", ns_status);

		ns_status_init(ns_status);
		list_add_tail(&ns_status->ns_node, &ns->ns_status_list);
	} else {
		ns_status_reset(ns_status);
	}

	ns_status->iint = iint;
	ns_status->inode = inode;
	ns_status->ns = ns;
	ns_status->i_ino = inode->i_ino;
	ns_status->i_generation = inode->i_generation;
	ns_status->ima_hash = NULL;

	/* make visible on list */
	write_lock(&iint->ns_list_lock);
	if (list_empty(&ns_status->ns_next))
		list_add_tail(&ns_status->ns_next, &iint->ns_list);
	write_unlock(&iint->ns_list_lock);

	write_unlock(&ns->ns_status_list_lock);

unlock:
	unlock_group(GRP_NS_STATUS_LIST);

	return ns_status;
}
