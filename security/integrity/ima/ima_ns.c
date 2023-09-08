// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2021 IBM Corporation
 * Author:
 *  Yuqiong Sun <suny@us.ibm.com>
 *  Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include <linux/ima.h>

#include "ima.h"

static struct kmem_cache *imans_cachep;

int ima_ns_set_tpm_chip(struct tpm_provider *tpm_provider,
			struct tpm_chip *tpm_chip)
{
	struct ima_namespace *ns = get_current_ns();
	int ret = 0;

	if (!ns)
		return -EINVAL;

	if (ns_is_active(ns))
		return -EBUSY;

	mutex_lock(&ns->tpm_provider_mutex);

	if (ns->ima_tpm_chip) {
		ret = -EBUSY;
	} else {
		ns->tpm_provider = tpm_provider;
		ns->ima_tpm_chip = tpm_chip;
	}

	mutex_unlock(&ns->tpm_provider_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(ima_ns_set_tpm_chip);

static struct ima_config *get_parent_config(struct user_namespace *user_ns)
{
	struct ima_namespace *ns;

	do {
		ns = ima_ns_from_user_ns(user_ns);
		if (ns_is_active(ns))
			return &ns->config;
		user_ns = user_ns->parent;
	} while (user_ns);

	/* init_ima_ns is always active, so this cannot happen */
	return NULL;
}

struct ima_namespace *create_ima_ns(struct user_namespace *user_ns)
{
	struct ima_config *ic = get_parent_config(user_ns);
	struct ima_namespace *ns;

	ns = kmem_cache_zalloc(imans_cachep, GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	/* inherit config from parent */
	ns->config = *ic;

	ns->integrity_ns = user_ns->integrity_ns;

	return ns;
}

/* destroy_ima_ns() must only be called after ima_init_namespace() was called */
static void destroy_ima_ns(struct ima_namespace *ns)
{
	clear_bit(IMA_NS_ACTIVE, &ns->ima_ns_flags);
	cancel_delayed_work_sync(&ns->ima_keys_delayed_work);
	ima_free_queued_keys(ns);
	unregister_blocking_lsm_notifier(&ns->ima_lsm_policy_notifier);
	kfree(ns->arch_policy_entry);
	ima_free_digests(ns);
	ima_deinit_crypto(ns);
	ima_free_policy_rules(ns);
	ima_free_ns_status_tree(ns);
	ima_free_measurements(ns);
}

void ima_free_ima_ns(struct ima_namespace *ns)
{
	if (!ns || WARN_ON(ns == &init_ima_ns))
		return;

	if (ns_is_active(ns))
		destroy_ima_ns(ns);

	if (ns->ima_tpm_chip)
		ns->tpm_provider->release_chip(ns->ima_tpm_chip);

	kmem_cache_free(imans_cachep, ns);
}

void free_ima_ns(struct user_namespace *user_ns)
{
	struct ima_namespace *ns = ima_ns_from_user_ns(user_ns);

	ima_free_ima_ns(ns);

	user_ns->integrity_ns->ima_ns = NULL;
}

static int __init imans_cache_init(void)
{
	imans_cachep = KMEM_CACHE(ima_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(imans_cache_init)
