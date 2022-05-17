// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2022 IBM Corporation
 * Author:
 *  Stefan Berger <stefanb@linux.ibm.com>
 */

#include <linux/evm.h>

#include "evm.h"

#ifdef CONFIG_IMA_NS

static struct kmem_cache *evmns_cachep;

struct evm_namespace *create_evm_ns(struct integrity_namespace *integrity_ns)
{
	struct evm_namespace *ns;
	int ret;

	ns = kmem_cache_zalloc(evmns_cachep, GFP_KERNEL);
	if (!ns)
		return ERR_PTR(-ENOMEM);

	ret = evm_init_namespace(ns, integrity_ns);
	if (ret) {
		kmem_cache_free(evmns_cachep, ns);
		ns = ERR_PTR(ret);
	}

	return ns;
}

void free_evm_ns(struct integrity_namespace *integrity_ns)
{
	struct evm_namespace *ns = integrity_ns->evm_ns;

	evm_ns_free_crypto(ns);
	evm_xattr_list_free_list(&ns->evm_config_xattrnames);
	kmem_cache_free(evmns_cachep, ns);
}

static int __init evmns_cache_init(void)
{
	evmns_cachep = KMEM_CACHE(evm_namespace, SLAB_PANIC);
	return 0;
}
subsys_initcall(evmns_cache_init)

#endif /* CONFIG_IMA_NS */
