/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Reiner Sailer <sailer@watson.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * File: ima.h
 *	internal Integrity Measurement Architecture (IMA) definitions
 */

#ifndef __LINUX_IMA_H
#define __LINUX_IMA_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/hash.h>
#include <linux/tpm.h>
#include <linux/audit.h>
#include <linux/user_namespace.h>
#include <linux/integrity_namespace.h>
#include <crypto/hash_info.h>

#include "../integrity.h"

enum ima_show_type { IMA_SHOW_BINARY, IMA_SHOW_BINARY_NO_FIELD_LEN,
		     IMA_SHOW_BINARY_OLD_STRING_FMT, IMA_SHOW_ASCII };
enum tpm_pcrs { TPM_PCR0 = 0, TPM_PCR8 = 8, TPM_PCR10 = 10 };

/* digest size for IMA, fits SHA1 or MD5 */
#define IMA_DIGEST_SIZE		SHA1_DIGEST_SIZE
#define IMA_EVENT_NAME_LEN_MAX	255

#define IMA_HASH_BITS 10
#define IMA_MEASURE_HTABLE_SIZE (1 << IMA_HASH_BITS)

#define IMA_TEMPLATE_FIELD_ID_MAX_LEN	16
#define IMA_TEMPLATE_NUM_FIELDS_MAX	15

#define IMA_TEMPLATE_IMA_NAME "ima"
#define IMA_TEMPLATE_IMA_FMT "d|n"

#define NR_BANKS(chip) ((chip != NULL) ? chip->nr_allocated_banks : 0)


extern const char boot_aggregate_name[];

/* IMA event related data */
struct ima_event_data {
	struct ima_digest_data *ima_hash;
	/* relevant iint/ns_status flags: IMA_VERITY_REQUIRED */
	unsigned long iint_flags;
	struct file *file;
	const unsigned char *filename;
	struct evm_ima_xattr_data *xattr_value;
	int xattr_len;
	const struct modsig *modsig;
	const char *violation;
	const void *buf;
	int buf_len;
	const uuid_t *src_userns;
};

/* IMA template field data definition */
struct ima_field_data {
	u8 *data;
	u32 len;
};

struct ima_namespace;

/* IMA template field definition */
struct ima_template_field {
	const char field_id[IMA_TEMPLATE_FIELD_ID_MAX_LEN];
	int (*field_init)(struct ima_namespace *ns,
			  struct ima_event_data *event_data,
			  struct ima_field_data *field_data);
	void (*field_show)(struct seq_file *m, enum ima_show_type show,
			   struct ima_field_data *field_data);
};

/* IMA template descriptor definition */
struct ima_template_desc {
	struct list_head list;
	char *name;
	char *fmt;
	int num_fields;
	const struct ima_template_field **fields;
};

struct ima_template_entry {
	int pcr;
	struct tpm_digest *digests;
	struct ima_template_desc *template_desc; /* template descriptor */
	u32 template_data_len;
	struct ima_field_data template_data[];	/* template related data */
};

struct ima_queue_entry {
	struct hlist_node hnext;	/* place in hash collision list */
	struct list_head later;		/* place in ima_measurements list */
	struct ima_template_entry *entry;
};

/* Some details preceding the binary serialized measurement list */
struct ima_kexec_hdr {
	u16 version;
	u16 _reserved0;
	u32 _reserved1;
	u64 buffer_size;
	u64 count;
};

struct ima_h_table {
	atomic_long_t len;	/* number of stored measurements in the list */
	atomic_long_t violations;
	struct hlist_head queue[IMA_MEASURE_HTABLE_SIZE];
};

/*
 * Configuration for init_ima_ns from boot line parameters and parameters for
 * IMA namespaces.
 */
struct ima_config {
	int ima_hash_algo;
	int hash_setup_done;

	char template_name[32];
};

struct ima_namespace {
	unsigned long ima_ns_flags;
/* Bit numbers for above flags; use BIT() to get flag */
#define IMA_NS_LSM_UPDATE_RULES		0
#define IMA_NS_ACTIVE			1
#define IMA_NS_DISABLED			2

	struct list_head ns_status_list;
	rwlock_t ns_status_list_lock;
	struct kmem_cache *ns_status_cache;

	/* policy rules */
	struct list_head ima_default_rules; /* Kconfig, builtin & arch rules */
	struct list_head ima_policy_rules;  /* arch & custom rules */
	struct list_head ima_temp_rules;

	struct list_head __rcu *ima_rules;  /* Pointer to the current policy */
	int ima_policy_flag;

	/* An array of architecture specific rules */
	struct ima_rule_entry *arch_policy_entry;

	struct ima_h_table ima_htable;
	struct list_head ima_measurements;	/* list of all measurements */
	unsigned long binary_runtime_size;	/* used by init_ima_ns */

	/*
	 * mutex protects atomicity of extending measurement list
	 * and extending the TPM PCR aggregate. Since tpm_extend can take
	 * long (and the tpm driver uses a mutex), we can't use the spinlock.
	 */
	struct mutex ima_extend_list_mutex;

	/* securityfs support related variables */
	struct mutex ima_write_mutex;
	unsigned long ima_fs_flags;
	int valid_policy;

	struct dentry *ima_policy;
	bool ima_policy_removed;

	struct notifier_block ima_lsm_policy_notifier;

	/* TPM and hash algo related */
	struct tpm_chip *ima_tpm_chip;
	struct tpm_digest *digests;
	struct ima_algo_desc *ima_algo_array;
	int ima_sha1_idx;
	int ima_hash_algo_idx;

	struct tpm_provider *tpm_provider;
	struct mutex tpm_provider_mutex;
	/*
	 * Additional number of slots reserved, as needed, for SHA1
	 * and IMA default algo.
	 */
	int ima_extra_slots;

	struct crypto_shash *ima_shash_tfm;
	struct crypto_ahash *ima_ahash_tfm;

	/*
	 * Flag to indicate whether a key can be processed
	 * right away or should be queued for processing later.
	 */
	bool ima_process_keys;

	struct ima_config config;

	struct ima_template_desc *ima_template;
	int template_setup_done;
	struct ima_template_desc *ima_buf_template;

#ifdef CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS
	/*
	 * Keys queue:
	 * To synchronize access to the list of keys that need to be measured
	 */
	struct mutex ima_keys_lock;
	struct list_head ima_keys;
	/*
	 * If custom IMA policy is not loaded then keys queued up
	 * for measurement should be freed. This worker is used
	 * for handling this scenario.
	 */
	long ima_key_queue_timeout;
	struct delayed_work ima_keys_delayed_work;
	bool timer_expired;
#endif

	struct integrity_namespace *integrity_ns;

	/* set during initialization */
	int ima_appraise;

	int temp_ima_appraise;

	/* bitset of digests algorithms allowed in the setxattr hook */
	atomic_t ima_setxattr_allowed_hash_algorithms;
} __randomize_layout;
extern struct ima_namespace init_ima_ns;

static inline bool ns_is_active(struct ima_namespace *ns)
{
	return (ns && test_bit(IMA_NS_ACTIVE, &ns->ima_ns_flags));
}

static inline bool ns_is_disabled(struct ima_namespace *ns)
{
	return (ns && test_bit(IMA_NS_DISABLED, &ns->ima_ns_flags));
}

extern const int read_idmap[];

#ifdef CONFIG_HAVE_IMA_KEXEC
void ima_load_kexec_buffer(void);
#else
static inline void ima_load_kexec_buffer(void) {}
#endif /* CONFIG_HAVE_IMA_KEXEC */

#ifdef CONFIG_IMA_MEASURE_ASYMMETRIC_KEYS
void ima_post_key_create_or_update(struct key *keyring, struct key *key,
				   const void *payload, size_t plen,
				   unsigned long flags, bool create);
#endif

/*
 * The default binary_runtime_measurements list format is defined as the
 * platform native format.  The canonical format is defined as little-endian.
 */
extern bool ima_canonical_fmt;

/* Internal IMA function definitions */
int ima_init(void);
int ima_fs_init(void);
int ima_ns_init(void);
int ima_init_namespace(struct ima_namespace *ns, uuid_t *src_userns);
int ima_add_template_entry(struct ima_namespace *ns,
			   struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename);
int ima_calc_file_hash(struct ima_namespace *ns,
		       struct file *file, struct ima_digest_data *hash);
int ima_calc_buffer_hash(struct ima_namespace *ns,
			 const void *buf, loff_t len,
			 struct ima_digest_data *hash);
int ima_calc_field_array_hash(struct ima_namespace *ns,
			      struct ima_field_data *field_data,
			      struct ima_template_entry *entry);
int ima_calc_boot_aggregate(struct ima_namespace *ns,
			    struct ima_digest_data *hash);
void ima_add_violation(struct ima_namespace *ns,
		       struct file *file, const unsigned char *filename,
		       struct integrity_iint_cache *iint,
		       struct ns_status *ns_status,
		       const char *op, const char *cause,
		       const uuid_t *src_userns);
int ima_init_crypto(struct ima_namespace *ns);
void ima_deinit_crypto(struct ima_namespace *ns);
void ima_putc(struct seq_file *m, void *data, int datalen);
void ima_print_digest(struct seq_file *m, u8 *digest, u32 size);
int template_desc_init_fields(const char *template_fmt,
			      const struct ima_template_field ***fields,
			      int *num_fields);
struct ima_template_desc *ima_template_desc_current(struct ima_namespace *ns,
						    const char *template_name);
struct ima_template_desc *ima_template_desc_buf(struct ima_namespace *ns);
struct ima_template_desc *lookup_template_desc(const char *name);
bool ima_template_has_modsig(const struct ima_template_desc *ima_template);
int ima_restore_measurement_entry(struct ima_namespace *ns,
				  struct ima_template_entry *entry);
int ima_restore_measurement_list(struct ima_namespace *ns,
				 loff_t bufsize, void *buf);
void ima_free_measurements(struct ima_namespace *ns);
int ima_ns_measurements_show(struct ima_namespace *ns,
			     struct seq_file *m, void *v);
unsigned long ima_get_binary_runtime_size(struct ima_namespace *ns);
int ima_init_template(struct ima_namespace *ns, const char *name);
void ima_init_template_list(void);
int ima_init_digests(struct ima_namespace *ns);
void ima_free_digests(struct ima_namespace *ns);
int ima_lsm_policy_change(struct notifier_block *nb, unsigned long event,
			  void *lsm_data);
int ima_add_boot_aggregate(struct ima_namespace *ns, uuid_t *src_userns);

/*
 * used to protect h_table and sha_table
 */
extern spinlock_t ima_queue_lock;

static inline unsigned int ima_hash_key(u8 *digest)
{
	/* there is no point in taking a hash of part of a digest */
	return (digest[0] | digest[1] << 8) % IMA_MEASURE_HTABLE_SIZE;
}

#define __ima_hooks(hook)				\
	hook(NONE, none)				\
	hook(FILE_CHECK, file)				\
	hook(MMAP_CHECK, mmap)				\
	hook(MMAP_CHECK_REQPROT, mmap_reqprot)		\
	hook(BPRM_CHECK, bprm)				\
	hook(CREDS_CHECK, creds)			\
	hook(POST_SETATTR, post_setattr)		\
	hook(MODULE_CHECK, module)			\
	hook(FIRMWARE_CHECK, firmware)			\
	hook(KEXEC_KERNEL_CHECK, kexec_kernel)		\
	hook(KEXEC_INITRAMFS_CHECK, kexec_initramfs)	\
	hook(POLICY_CHECK, policy)			\
	hook(KEXEC_CMDLINE, kexec_cmdline)		\
	hook(KEY_CHECK, key)				\
	hook(CRITICAL_DATA, critical_data)		\
	hook(SETXATTR_CHECK, setxattr_check)		\
	hook(MAX_CHECK, none)

#define __ima_hook_enumify(ENUM, str)	ENUM,
#define __ima_stringify(arg) (#arg)
#define __ima_hook_measuring_stringify(ENUM, str) \
		(__ima_stringify(measuring_ ##str)),

enum ima_hooks {
	__ima_hooks(__ima_hook_enumify)
};

static const char * const ima_hooks_measure_str[] = {
	__ima_hooks(__ima_hook_measuring_stringify)
};

static inline const char *func_measure_str(enum ima_hooks func)
{
	if (func >= MAX_CHECK)
		return ima_hooks_measure_str[NONE];

	return ima_hooks_measure_str[func];
}

extern const char *const func_tokens[];

struct modsig;

#ifdef CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS
/*
 * To track keys that need to be measured.
 */
struct ima_key_entry {
	struct list_head list;
	void *payload;
	size_t payload_len;
	char *keyring_name;
};
void ima_init_key_queue(struct ima_namespace *ns);
bool ima_should_queue_key(struct ima_namespace *ns);
bool ima_queue_key(struct ima_namespace *ns, struct key *keyring,
		   const void *payload, size_t payload_len);
void ima_process_queued_keys(struct ima_namespace *ns);
/*
 * If custom IMA policy is not loaded then keys queued up
 * for measurement should be freed. This worker is used
 * for handling this scenario.
 */
void ima_keys_handler(struct work_struct *work);

void ima_free_queued_keys(struct ima_namespace *ns);
#else
static inline void ima_init_key_queue(struct ima_namespace *ns) {}
static inline bool ima_should_queue_key(struct ima_namespace *ns)
{
	return false;
}
static inline bool ima_queue_key(struct ima_namespace *ns,
				 struct key *keyring,
				 const void *payload,
				 size_t payload_len) { return false; }
static inline void ima_process_queued_keys(struct ima_namespace *ns) {}
static inline void ima_free_queued_keys(struct ima_namespace *ns) {}
#endif /* CONFIG_IMA_QUEUE_EARLY_BOOT_KEYS */

/* LIM API function definitions */
int ima_get_action(struct ima_namespace *ns,
		   struct mnt_idmap *idmap, struct inode *inode,
		   const struct cred *cred, u32 secid, int mask,
		   enum ima_hooks func, int *pcr,
		   struct ima_template_desc **template_desc,
		   const char *func_data, unsigned int *allowed_algos);
int ima_must_measure(struct inode *inode, int mask, enum ima_hooks func);
int ima_collect_measurement(struct ima_namespace *ns,
			    struct integrity_iint_cache *iint,
			    struct ns_status *ns_status,
			    struct file *file, void *buf, loff_t size,
			    enum hash_algo algo, struct modsig *modsig);
void ima_store_measurement(struct user_namespace *user_ns,
			   struct integrity_iint_cache *iint, struct file *file,
			   const unsigned char *filename,
			   struct evm_ima_xattr_data *xattr_value,
			   int xattr_len, const struct modsig *modsig, int pcr,
			   struct ima_template_desc *template_desc,
			   struct ns_status *ns_status,
			   const uuid_t *src_userns);
int process_buffer_measurement(struct ima_namespace *ns,
			       struct mnt_idmap *idmap,
			       struct inode *inode, const void *buf, int size,
			       const char *eventname, enum ima_hooks func,
			       int pcr, const char *func_data,
			       bool buf_hash, u8 *digest, size_t digest_len,
			       uuid_t *src_userns);
void ima_audit_measurement(struct integrity_iint_cache *iint,
			   const unsigned char *filename,
			   struct ns_status *ns_status);
int ima_alloc_init_template(struct ima_namespace *ns,
			    struct ima_event_data *event_data,
			    struct ima_template_entry **entry,
			    struct ima_template_desc *template_desc);
int ima_store_template(struct ima_namespace *ns,
		       struct ima_template_entry *entry, int violation,
		       struct inode *inode,
		       const unsigned char *filename, int pcr);
void ima_free_template_entry(struct ima_template_entry *entry);
const char *ima_d_path(const struct path *path, char **pathbuf, char *filename);

/* IMA policy related functions */
int ima_match_policy(struct ima_namespace *ns,
		     struct mnt_idmap *idmap, struct inode *inode,
		     const struct cred *cred, u32 secid, enum ima_hooks func,
		     int mask, int flags, int *pcr,
		     struct ima_template_desc **template_desc,
		     const char *func_data, unsigned int *allowed_algos);
void ima_init_policy(struct user_namespace *user_ns);
void ima_update_policy(struct ima_namespace *ns);
void ima_update_policy_flags(struct ima_namespace *ns);
ssize_t ima_parse_add_rule(struct user_namespace *user_ns, char *rule);
void ima_delete_rules(struct ima_namespace *ns);
int ima_check_policy(struct ima_namespace *ns);
void ima_free_policy_rules(struct ima_namespace *ns);
void *ima_policy_start(struct seq_file *m, loff_t *pos);
void *ima_policy_next(struct seq_file *m, void *v, loff_t *pos);
void ima_policy_stop(struct seq_file *m, void *v);
int ima_policy_show(struct seq_file *m, void *v);

/* Appraise integrity measurements */
#define IMA_APPRAISE_ENFORCE	0x01
#define IMA_APPRAISE_FIX	0x02
#define IMA_APPRAISE_LOG	0x04
#define IMA_APPRAISE_MODULES	0x08
#define IMA_APPRAISE_FIRMWARE	0x10
#define IMA_APPRAISE_POLICY	0x20
#define IMA_APPRAISE_KEXEC	0x40

#ifdef CONFIG_IMA_APPRAISE
int ima_check_blacklist(struct ima_namespace *ns,
			struct integrity_iint_cache *iint,
			struct ns_status *ns_status,
			const struct modsig *modsig, int pcr);
int ima_appraise_measurement(struct ima_namespace *ns,
			     enum ima_hooks func,
			     struct integrity_iint_cache *iint,
			     struct ns_status *ns_status,
			     struct file *file, const unsigned char *filename,
			     struct evm_ima_xattr_data *xattr_value,
			     int xattr_len, const struct modsig *modsig);
int ima_must_appraise(struct ima_namespace *ns,
		      struct mnt_idmap *idmap, struct inode *inode,
		      int mask, enum ima_hooks func);
void ima_update_xattr(struct ima_namespace *ns,
		      struct integrity_iint_cache *iint, struct file *file);
enum integrity_status ima_get_cache_status(struct ns_status *ns_status,
					   enum ima_hooks func);
enum hash_algo ima_get_hash_algo(struct ima_namespace *ns,
				 const struct evm_ima_xattr_data *xattr_value,
				 int xattr_len);
int ima_read_xattr(struct dentry *dentry,
		   struct evm_ima_xattr_data **xattr_value, int xattr_len);
void __init init_ima_appraise_lsm(void);

#else
static inline int ima_check_blacklist(struct ima_namespace *ns,
				      struct integrity_iint_cache *iint,
				      struct ns_status *ns_status,
				      const struct modsig *modsig, int pcr)
{
	return 0;
}

static inline int ima_appraise_measurement(struct ima_namespace *ns,
					   enum ima_hooks func,
					   struct integrity_iint_cache *iint,
					   struct ns_status *ns_status,
					   struct file *file,
					   const unsigned char *filename,
					   struct evm_ima_xattr_data *xattr_value,
					   int xattr_len,
					   const struct modsig *modsig)
{
	return INTEGRITY_UNKNOWN;
}

static inline int ima_must_appraise(struct ima_namespace *ns,
				    struct mnt_idmap *idmap,
				    struct inode *inode, int mask,
				    enum ima_hooks func)
{
	return 0;
}

static inline void ima_update_xattr(struct ima_namespace *ns,
				    struct integrity_iint_cache *iint,
				    struct file *file)
{
}

static inline enum integrity_status ima_get_cache_status(struct ns_status
							 *ns_status,
							 enum ima_hooks func)
{
	return INTEGRITY_UNKNOWN;
}

static inline enum hash_algo
ima_get_hash_algo(struct ima_namespace *ns,
		  struct evm_ima_xattr_data *xattr_value, int xattr_len)
{
	return ns->config.ima_hash_algo;
}

static inline int ima_read_xattr(struct dentry *dentry,
				 struct evm_ima_xattr_data **xattr_value,
				 int xattr_len)
{
	return 0;
}

static inline void __init init_ima_appraise_lsm(void)
{
}

#endif /* CONFIG_IMA_APPRAISE */

#ifdef CONFIG_IMA_APPRAISE_MODSIG
int ima_read_modsig(enum ima_hooks func, const void *buf, loff_t buf_len,
		    struct modsig **modsig);
void ima_collect_modsig(struct modsig *modsig, const void *buf, loff_t size);
int ima_get_modsig_digest(const struct modsig *modsig, enum hash_algo *algo,
			  const u8 **digest, u32 *digest_size);
int ima_get_raw_modsig(const struct modsig *modsig, const void **data,
		       u32 *data_len);
void ima_free_modsig(struct modsig *modsig);
#else
static inline int ima_read_modsig(enum ima_hooks func, const void *buf,
				  loff_t buf_len, struct modsig **modsig)
{
	return -EOPNOTSUPP;
}

static inline void ima_collect_modsig(struct modsig *modsig, const void *buf,
				      loff_t size)
{
}

static inline int ima_get_modsig_digest(const struct modsig *modsig,
					enum hash_algo *algo, const u8 **digest,
					u32 *digest_size)
{
	return -EOPNOTSUPP;
}

static inline int ima_get_raw_modsig(const struct modsig *modsig,
				     const void **data, u32 *data_len)
{
	return -EOPNOTSUPP;
}

static inline void ima_free_modsig(struct modsig *modsig)
{
}
#endif /* CONFIG_IMA_APPRAISE_MODSIG */

/* LSM based policy rules require audit */
#ifdef CONFIG_IMA_LSM_RULES

#define ima_filter_rule_init security_audit_rule_init
#define ima_filter_rule_free security_audit_rule_free
#define ima_filter_rule_match security_audit_rule_match

#else

static inline int ima_filter_rule_init(u32 field, u32 op, char *rulestr,
				       void **lsmrule)
{
	return -EINVAL;
}

static inline void ima_filter_rule_free(void *lsmrule)
{
}

static inline int ima_filter_rule_match(u32 secid, u32 field, u32 op,
					void *lsmrule)
{
	return -EINVAL;
}
#endif /* CONFIG_IMA_LSM_RULES */

#ifdef	CONFIG_IMA_READ_POLICY
#define	POLICY_FILE_FLAGS	(S_IWUSR | S_IRUSR)
#else
#define	POLICY_FILE_FLAGS	S_IWUSR
#endif /* CONFIG_IMA_READ_POLICY */

#define IMA_NS_STATUS_ACTIONS   (IMA_AUDIT | IMA_MEASURE | IMA_APPRAISE | \
				 IMA_HASH)
#define IMA_NS_STATUS_FLAGS     (IMA_AUDIT | IMA_AUDITED | \
				 IMA_MEASURE | IMA_MEASURED | IMA_COLLECTED | \
				 IMA_PERMIT_DIRECTIO | IMA_DIGSIG_REQUIRED | \
				 IMA_MODSIG_ALLOWED | IMA_CHECK_BLACKLIST | \
				 IMA_APPRAISE | IMA_APPRAISED | \
				 IMA_FILE_APPRAISED | IMA_MMAP_APPRAISED | \
				 IMA_BPRM_APPRAISED | IMA_READ_APPRAISED | \
				 IMA_CREDS_APPRAISED | IMA_READ_APPRAISED | \
				 IMA_HASH | IMA_HASHED)

static inline unsigned long iint_flags(struct integrity_iint_cache *iint,
				       struct ns_status *ns_status)
{
#if 0
	// this may cause unrelated RCU related error messages
	if (!mutex_is_locked(&iint->mutex))
		WARN_ON(true);
#endif
	if (!ns_status)
		return iint->flags;

	return (iint->flags & ~IMA_NS_STATUS_FLAGS) |
	       (ns_status->flags & IMA_NS_STATUS_FLAGS);
}

static inline unsigned long set_iint_flags(struct integrity_iint_cache *iint,
					   struct ns_status *ns_status,
					   unsigned long flags)
{
	unsigned long ns_status_flags = flags & IMA_NS_STATUS_FLAGS;

#if 0
	// this may cause unrelated RCU related error messages
	if (!mutex_is_locked(&iint->mutex))
		WARN_ON(true);
#endif
	WARN_ON(!ns_status && ns_status_flags);

	iint->flags = flags & ~IMA_NS_STATUS_FLAGS;
	if (ns_status)
		ns_status->flags = ns_status_flags;

	return flags;
}

static inline
struct user_namespace *ima_user_ns_from_file(const struct file *filp)
{
	return file_sb_user_ns(filp);
}

#ifdef CONFIG_IMA_NS

static inline struct ima_namespace
*ima_ns_from_user_ns(struct user_namespace *user_ns)
{
	/* Pairs with smp_store_releases() in user_ns_set_ima_ns(). */
	return smp_load_acquire(&user_ns->integrity_ns->ima_ns);
}

static inline void user_ns_set_ima_ns(struct user_namespace *user_ns,
				      struct ima_namespace *ns)
{
	/* Pairs with smp_load_acquire() in ima_ns_from_user_ns() */
	smp_store_release(&user_ns->integrity_ns->ima_ns, ns);
}

static inline struct ima_namespace *get_current_ns(void)
{
	return ima_ns_from_user_ns(current_user_ns());
}

struct ima_namespace *create_ima_ns(struct user_namespace *user_ns);

void ima_free_ima_ns(struct ima_namespace *ns);

struct ns_status *ima_get_ns_status(struct ima_namespace *ns,
				    struct inode *inode,
				    struct integrity_iint_cache *iint);

void ima_ns_free_ns_status_list(struct ima_namespace *ns);

static inline struct ima_namespace *ima_ns_from_file(const struct file *filp)
{
	struct user_namespace *user_ns = ima_user_ns_from_file(filp);

	return ima_ns_from_user_ns(user_ns);
}

#else

static inline struct ima_namespace
*ima_ns_from_user_ns(struct user_namespace *user_ns)
{
	if (user_ns == &init_user_ns)
		return &init_ima_ns;
	return NULL;
}

static inline void user_ns_set_ima_ns(struct user_namespace *user_ns,
				      struct ima_namespace *ns)
{
}

static inline struct ima_namespace *get_current_ns(void)
{
	return &init_ima_ns;
}

static inline struct ima_namespace *
create_ima_ns(struct user_namespace *user_ns)
{
	WARN(1, "Cannot create an IMA namespace\n");
	return ERR_PTR(-EFAULT);
}

static inline void ima_free_ima_ns(struct ima_namespace *ns) {}

static inline struct ns_status *ima_get_ns_status
					(struct ima_namespace *ns,
					 struct inode *inode,
					 struct integrity_iint_cache *iint)
{
	struct ns_status *ns_status = &iint->ns_status;

	if (list_empty(&iint->ns_list)) {
		ns_status_init(ns_status);
		ns_status->ns = &init_ima_ns;
		list_add(&ns_status->ns_next, &iint->ns_list);
	}

	return ns_status;
}

static inline struct ima_namespace *ima_ns_from_file(const struct file *filp)
{
	return &init_ima_ns;
}

#endif /* CONFIG_IMA_NS */

static inline int filename_contains(struct file *file, const char *needle)
{
	char *pathbuf = NULL;
	char filename[NAME_MAX];
	const char *pathname = NULL;
	int b = 0;

	pathname = ima_d_path(&file->f_path, &pathbuf, filename);
	if (pathbuf) {
		b = (strstr(pathname, needle) != NULL);
		__putname(pathbuf);
	}
	return b;
}


#endif /* __LINUX_IMA_H */
