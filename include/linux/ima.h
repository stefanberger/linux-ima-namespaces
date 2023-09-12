/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2008 IBM Corporation
 * Author: Mimi Zohar <zohar@us.ibm.com>
 */

#ifndef _LINUX_IMA_H
#define _LINUX_IMA_H

#include <linux/kernel_read_file.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/kexec.h>
#include <crypto/hash_info.h>
struct linux_binprm;

extern struct ima_namespace init_ima_ns;

#ifdef CONFIG_IMA
extern enum hash_algo ima_get_current_hash_algo(void);
extern int ima_file_check(struct file *file, int mask);
extern int ima_file_hash(struct file *file, char *buf, size_t buf_size);
extern int ima_inode_hash(struct inode *inode, char *buf, size_t buf_size);
extern void ima_kexec_cmdline(int kernel_fd, const void *buf, int size);
extern int ima_measure_critical_data(const char *event_label,
				     const char *event_name,
				     const void *buf, size_t buf_len,
				     bool hash, u8 *digest, size_t digest_len);
extern int ima_fs_ns_init(struct user_namespace *user_ns, struct dentry *root);

#ifdef CONFIG_IMA_APPRAISE_BOOTPARAM
extern void ima_appraise_parse_cmdline(void);
#else
static inline void ima_appraise_parse_cmdline(void) {}
#endif

#ifdef CONFIG_IMA_KEXEC
extern void ima_add_kexec_buffer(struct kimage *image);
#endif

#else
static inline enum hash_algo ima_get_current_hash_algo(void)
{
	return HASH_ALGO__LAST;
}

static inline int ima_file_check(struct file *file, int mask)
{
	return 0;
}

static inline int ima_file_hash(struct file *file, char *buf, size_t buf_size)
{
	return -EOPNOTSUPP;
}

static inline int ima_inode_hash(struct inode *inode, char *buf, size_t buf_size)
{
	return -EOPNOTSUPP;
}

static inline void ima_kexec_cmdline(int kernel_fd, const void *buf, int size) {}

static inline int ima_measure_critical_data(const char *event_label,
					     const char *event_name,
					     const void *buf, size_t buf_len,
					     bool hash, u8 *digest,
					     size_t digest_len)
{
	return -ENOENT;
}

#endif /* CONFIG_IMA */

#ifdef CONFIG_HAVE_IMA_KEXEC
int __init ima_free_kexec_buffer(void);
int __init ima_get_kexec_buffer(void **addr, size_t *size);
#endif

#ifdef CONFIG_IMA_SECURE_AND_OR_TRUSTED_BOOT
extern bool arch_ima_get_secureboot(void);
extern const char * const *arch_get_ima_policy(void);
#else
static inline bool arch_ima_get_secureboot(void)
{
	return false;
}

static inline const char * const *arch_get_ima_policy(void)
{
	return NULL;
}
#endif

#ifndef CONFIG_IMA_KEXEC
struct kimage;

static inline void ima_add_kexec_buffer(struct kimage *image)
{}
#endif

#ifdef CONFIG_IMA_APPRAISE
extern bool is_ima_appraise_enabled(void);
#else
static inline bool is_ima_appraise_enabled(void)
{
	return 0;
}
#endif /* CONFIG_IMA_APPRAISE */

#if defined(CONFIG_IMA_APPRAISE) && defined(CONFIG_INTEGRITY_TRUSTED_KEYRING)
extern bool ima_appraise_signature(enum kernel_read_file_id func);
#else
static inline bool ima_appraise_signature(enum kernel_read_file_id func)
{
	return false;
}
#endif /* CONFIG_IMA_APPRAISE && CONFIG_INTEGRITY_TRUSTED_KEYRING */

#ifdef CONFIG_IMA_NS

void free_ima_ns(struct user_namespace *ns);

void ima_free_ns_status_list(struct list_head *head, rwlock_t *ns_list_lock);

static inline int ima_securityfs_init(struct user_namespace *user_ns,
				      struct dentry *root)
{
	return ima_fs_ns_init(user_ns, root);
}

#else

static inline void free_ima_ns(struct user_namespace *user_ns)
{
}

static inline void ima_free_ns_status_list(struct list_head *head,
					   rwlock_t *ns_list_lock)
{
}

static inline int ima_securityfs_init(struct user_namespace *ns,
				      struct dentry *root)
{
	return 0;
}

#endif /* CONFIG_IMA_NS */

#endif /* _LINUX_IMA_H */
