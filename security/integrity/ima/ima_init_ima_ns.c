// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016-2021 IBM Corporation
 * Author:
 *   Yuqiong Sun <suny@us.ibm.com>
 *   Stefan Berger <stefanb@linux.vnet.ibm.com>
 */

#include "ima.h"

static int ima_init_namespace(struct ima_namespace *ns)
{
	INIT_LIST_HEAD(&ns->ima_default_rules);
	INIT_LIST_HEAD(&ns->ima_policy_rules);
	INIT_LIST_HEAD(&ns->ima_temp_rules);
	ns->ima_rules = (struct list_head __rcu *)(&ns->ima_default_rules);
	ns->ima_policy_flag = 0;

	atomic_long_set(&ns->ima_htable.len, 0);
	atomic_long_set(&ns->ima_htable.violations, 0);
	memset(&ns->ima_htable.queue, 0, sizeof(ns->ima_htable.queue));

	return 0;
}

int __init ima_ns_init(void)
{
	return ima_init_namespace(&init_ima_ns);
}

struct ima_namespace init_ima_ns = {
};
EXPORT_SYMBOL(init_ima_ns);
