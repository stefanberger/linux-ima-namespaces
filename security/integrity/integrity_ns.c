// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 IBM Corporation
 *
 * Authors:
 * Stefan Berger <stefanb@us.ibm.com>
 */

#include <linux/slab.h>
#include <linux/evm.h>
#include <linux/ima.h>
#include <linux/integrity_namespace.h>

#include "integrity.h"

struct integrity_namespace init_integrity_ns = {
#ifdef CONFIG_IMA
	.ima_ns = &init_ima_ns,
#endif
#ifdef CONFIG_EVM
	.evm_ns = &init_evm_ns,
#endif
	.keyring = {NULL, },
	.keyring_name = {
#ifndef CONFIG_INTEGRITY_TRUSTED_KEYRING
		"_evm",
		"_ima",
#else
		".evm",
		".ima",
#endif
		".platform",
		".machine",
	},
};
EXPORT_SYMBOL(init_integrity_ns);

#ifdef CONFIG_IMA_NS

static struct kmem_cache *integrityns_cachep;

struct integrity_namespace *create_integrity_ns(void)
{
	struct integrity_namespace *ns;

	ns = kmem_cache_zalloc(integrityns_cachep, GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

#ifdef CONFIG_EVM
	ns->evm_ns = create_evm_ns(ns);
	if (IS_ERR(ns->evm_ns)) {
		kmem_cache_free(integrityns_cachep, ns);
		return ERR_PTR(PTR_ERR(ns->evm_ns));
	}
#endif

	ns->keyring_name[INTEGRITY_KEYRING_EVM] = "_evm";
	ns->keyring_name[INTEGRITY_KEYRING_IMA] = "_ima";
	ns->keyring_name[INTEGRITY_KEYRING_PLATFORM] = "";
	ns->keyring_name[INTEGRITY_KEYRING_MACHINE] = "";

	return ns;
}

void free_integrity_ns(struct user_namespace *user_ns)
{
	struct integrity_namespace *ns = user_ns->integrity_ns;
	size_t i;

	free_ima_ns(user_ns);
#ifdef CONFIG_EVM
	free_evm_ns(ns);
#endif
	integrity_fs_free(ns);

	for (i = 0; i < ARRAY_SIZE(ns->keyring); i++)
		key_put(ns->keyring[i]);

	kmem_cache_free(integrityns_cachep, ns);
}

static int __init integrityns_cache_init(void)
{
	integrityns_cachep = KMEM_CACHE(integrity_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(integrityns_cache_init)

#endif
