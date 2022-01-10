/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 IBM Corporation
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef _LINUX_INTEGRITY_NAMESPACE_H
#define _LINUX_INTEGRITY_NAMESPACE_H

#include <linux/cred.h>
#include <linux/user_namespace.h>

#define INTEGRITY_KEYRING_EVM		0
#define INTEGRITY_KEYRING_IMA		1
#define INTEGRITY_KEYRING_PLATFORM	2
#define INTEGRITY_KEYRING_MACHINE	3
#define INTEGRITY_KEYRING_MAX		4

struct ima_namespace;
struct evm_namespace;

struct integrity_namespace {
#ifdef CONFIG_IMA
	struct ima_namespace *ima_ns;
#endif
#ifdef CONFIG_EVM
	struct evm_namespace *evm_ns;
#endif
	struct key *keyring[INTEGRITY_KEYRING_MAX];
	const char *keyring_name[INTEGRITY_KEYRING_MAX];
	struct dentry *integrity_dir;
};

extern struct integrity_namespace init_integrity_ns;

/* Functions to get evm_ns */
#ifdef CONFIG_EVM
static inline struct evm_namespace *integrity_ns_get_evm_ns
					(struct integrity_namespace *ns)
{
	return ns->evm_ns;
}
#else
static inline struct evm_namespace *integrity_ns_get_evm_ns
					(struct integrity_namespace *ns)
{
	return NULL;
}
#endif

#ifdef CONFIG_IMA_NS

static inline struct integrity_namespace *current_integrity_ns(void)
{
	return current_user_ns()->integrity_ns;
}

struct integrity_namespace *create_integrity_ns(void);

void free_integrity_ns(struct user_namespace *user_ns);

#else

static inline struct integrity_namespace *current_integrity_ns(void)
{
	return &init_integrity_ns;
}

static inline struct integrity_namespace *create_integrity_ns(void)
{
	return NULL;
}

static inline void free_integrity_ns(struct user_namespace *user_ns)
{
}

#endif /* CONFIG_IMA_NS */

#endif /* _LINUX_INTEGRITY_NAMESPACE_H */
