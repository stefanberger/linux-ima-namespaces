// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2022 IBM Corporation
 * Author:
 *   Yuqiong Sun <suny@us.ibm.com>
 *   Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include "ima.h"

int ima_init_namespace(struct ima_namespace *ns)
{
	int ret;

	ns->ns_status_tree = RB_ROOT;
	rwlock_init(&ns->ns_tree_lock);
	/* Use KMEM_CACHE for simplicity */
	ns->ns_status_cache = KMEM_CACHE(ns_status, SLAB_PANIC);

	INIT_LIST_HEAD(&ns->ima_default_rules);
	INIT_LIST_HEAD(&ns->ima_policy_rules);
	INIT_LIST_HEAD(&ns->ima_temp_rules);
	ns->ima_rules = (struct list_head __rcu *)(&ns->ima_default_rules);
	ns->ima_policy_flag = 0;
	ns->arch_policy_entry = NULL;

	atomic_long_set(&ns->ima_htable.len, 0);
	atomic_long_set(&ns->ima_htable.violations, 0);
	memset(&ns->ima_htable.queue, 0, sizeof(ns->ima_htable.queue));
	INIT_LIST_HEAD(&ns->ima_measurements);
	if (IS_ENABLED(CONFIG_IMA_KEXEC) && ns == &init_ima_ns)
		ns->binary_runtime_size = 0;
	else
		ns->binary_runtime_size = ULONG_MAX;
	mutex_init(&ns->ima_extend_list_mutex);

	mutex_init(&ns->ima_write_mutex);
	ns->valid_policy = 1;
	ns->ima_fs_flags = 0;

	if (ns != &init_ima_ns) {
		ns->ima_lsm_policy_notifier.notifier_call =
						ima_lsm_policy_change;
		ret = register_blocking_lsm_notifier
						(&ns->ima_lsm_policy_notifier);
		if (ret)
			goto err_destroy_cache;
	}

	if (ns == &init_ima_ns) {
		ns->ima_tpm_chip = tpm_default_chip(&init_user_ns);
		if (!ns->ima_tpm_chip)
			pr_info("No TPM chip found, activating TPM-bypass!\n");
	}

	ret = ima_init_crypto(ns);
	if (ret < 0)
		goto err_deregister_notifier;

	set_bit(IMA_NS_ACTIVE, &ns->ima_ns_flags);

	return 0;

err_deregister_notifier:
	unregister_blocking_lsm_notifier(&ns->ima_lsm_policy_notifier);

err_destroy_cache:
	kmem_cache_destroy(ns->ns_status_cache);

	return ret;
}

int __init ima_ns_init(void)
{
	return ima_init_namespace(&init_ima_ns);
}

struct ima_namespace init_ima_ns = {
	.ima_lsm_policy_notifier = {
		.notifier_call = ima_lsm_policy_change,
	},
	.ima_ns_flags = BIT(IMA_NS_ACTIVE),
};
EXPORT_SYMBOL(init_ima_ns);
