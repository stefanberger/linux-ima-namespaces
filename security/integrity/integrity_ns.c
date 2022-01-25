// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 IBM Corporation
 *
 * Authors:
 * Stefan Berger <stefanb@us.ibm.com>
 */

#include <linux/ima.h>
#include <linux/integrity_namespace.h>

struct integrity_namespace init_integrity_ns = {
#ifdef CONFIG_IMA
	.ima_ns = &init_ima_ns,
#endif
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

	return ns;
}

void free_integrity_ns(struct user_namespace *user_ns)
{
	struct integrity_namespace *ns = user_ns->integrity_ns;

	free_ima_ns(user_ns);

	kmem_cache_free(integrityns_cachep, ns);
}

static int __init integrityns_cache_init(void)
{
	integrityns_cachep = KMEM_CACHE(integrity_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(integrityns_cache_init)

#endif
