/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 IBM Corporation
 * Author: Stefan Berger <stefanb@us.ibm.com>
 */

#ifndef _LINUX_INTEGRITY_NAMESPACE_H
#define _LINUX_INTEGRITY_NAMESPACE_H

struct ima_namespace;

struct integrity_namespace {
#ifdef CONFIG_IMA
	struct ima_namespace *ima_ns;
#endif
};

extern struct integrity_namespace init_integrity_ns;

#ifdef CONFIG_IMA_NS

struct integrity_namespace *create_integrity_ns(void);
void free_integrity_ns(struct user_namespace *user_ns);

#else

static inline struct integrity_namespace *create_integrity_ns(void)
{
	return NULL;
}

static inline void free_integrity_ns(struct user_namespace *user_ns)
{
}

#endif /* CONFIG_IMA_NS */

#endif /* _LINUX_INTEGRITY_NAMESPACE_H */
