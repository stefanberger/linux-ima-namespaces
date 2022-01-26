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
	const char *template_name = NULL;
	int ret;

	INIT_LIST_HEAD(&ns->ns_status_list);
	rwlock_init(&ns->ns_status_list_lock);
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

	if (ns == &init_ima_ns)
		ns->ima_process_keys = false;
	else
		ns->ima_process_keys = true;

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

	if (ns != &init_ima_ns)
		template_name = ns->config.template_name;
	ret = ima_init_template(ns, template_name);
	if (ret != 0)
		goto err_deinit_crypto;

	ret = ima_init_digests(ns);
	if (ret)
		goto err_deinit_crypto;

	if (ns != &init_ima_ns) {
		/* boot aggregate must be first entry */
		ret = ima_add_boot_aggregate(ns);
		if (ret != 0)
			goto err_free_digests;
	}

	set_bit(IMA_NS_ACTIVE, &ns->ima_ns_flags);

	return 0;

err_free_digests:
	ima_free_digests(ns);

err_deinit_crypto:
	ima_deinit_crypto(ns);

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
	.config = {
		.ima_hash_algo = HASH_ALGO_SHA1,
		.template_name = CONFIG_IMA_DEFAULT_TEMPLATE,
	},
};
EXPORT_SYMBOL(init_ima_ns);
