/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2009-2010 IBM Corporation
 *
 * Authors:
 * Mimi Zohar <zohar@us.ibm.com>
 */

#ifdef pr_fmt
#undef pr_fmt
#endif

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/types.h>
#include <linux/integrity.h>
#include <crypto/sha1.h>
#include <crypto/hash.h>
#include <linux/key.h>
#include <linux/audit.h>
#include <linux/lsm_hooks.h>

/* iint action cache flags */
#define IMA_MEASURE		0x00000001
#define IMA_MEASURED		0x00000002
#define IMA_APPRAISE		0x00000004
#define IMA_APPRAISED		0x00000008
/*#define IMA_COLLECT		0x00000010  do not use this flag */
#define IMA_COLLECTED		0x00000020
#define IMA_AUDIT		0x00000040
#define IMA_AUDITED		0x00000080
#define IMA_HASH		0x00000100
#define IMA_HASHED		0x00000200

/* iint policy rule cache flags */
#define IMA_NONACTION_FLAGS	0xff000000
#define IMA_DIGSIG_REQUIRED	0x01000000
#define IMA_PERMIT_DIRECTIO	0x02000000
#define IMA_NEW_FILE		0x04000000
#define EVM_IMMUTABLE_DIGSIG	0x08000000
#define IMA_FAIL_UNVERIFIABLE_SIGS	0x10000000
#define IMA_MODSIG_ALLOWED	0x20000000
#define IMA_CHECK_BLACKLIST	0x40000000
#define IMA_VERITY_REQUIRED	0x80000000

#define IMA_DO_MASK		(IMA_MEASURE | IMA_APPRAISE | IMA_AUDIT | \
				 IMA_HASH | IMA_APPRAISE_SUBMASK)
#define IMA_DONE_MASK		(IMA_MEASURED | IMA_APPRAISED | IMA_AUDITED | \
				 IMA_HASHED | IMA_COLLECTED | \
				 IMA_APPRAISED_SUBMASK)

/* iint subaction appraise cache flags */
#define IMA_FILE_APPRAISE	0x00001000
#define IMA_FILE_APPRAISED	0x00002000
#define IMA_MMAP_APPRAISE	0x00004000
#define IMA_MMAP_APPRAISED	0x00008000
#define IMA_BPRM_APPRAISE	0x00010000
#define IMA_BPRM_APPRAISED	0x00020000
#define IMA_READ_APPRAISE	0x00040000
#define IMA_READ_APPRAISED	0x00080000
#define IMA_CREDS_APPRAISE	0x00100000
#define IMA_CREDS_APPRAISED	0x00200000
#define IMA_APPRAISE_SUBMASK	(IMA_FILE_APPRAISE | IMA_MMAP_APPRAISE | \
				 IMA_BPRM_APPRAISE | IMA_READ_APPRAISE | \
				 IMA_CREDS_APPRAISE)
#define IMA_APPRAISED_SUBMASK	(IMA_FILE_APPRAISED | IMA_MMAP_APPRAISED | \
				 IMA_BPRM_APPRAISED | IMA_READ_APPRAISED | \
				 IMA_CREDS_APPRAISED)

/* iint cache atomic_flags */
#define IMA_CHANGE_XATTR	0
#define IMA_UPDATE_XATTR	1
#define IMA_CHANGE_ATTR		2
#define IMA_DIGSIG		3
#define IMA_MUST_MEASURE	4	/* in ns_status's atomic_flags */

enum evm_ima_xattr_type {
	IMA_XATTR_DIGEST = 0x01,
	EVM_XATTR_HMAC,
	EVM_IMA_XATTR_DIGSIG,
	IMA_XATTR_DIGEST_NG,
	EVM_XATTR_PORTABLE_DIGSIG,
	IMA_VERITY_DIGSIG,
	IMA_XATTR_LAST
};

struct evm_ima_xattr_data {
	u8 type;
	u8 data[];
} __packed;

/* Only used in the EVM HMAC code. */
struct evm_xattr {
	struct evm_ima_xattr_data data;
	u8 digest[SHA1_DIGEST_SIZE];
} __packed;

#define IMA_MAX_DIGEST_SIZE	HASH_MAX_DIGESTSIZE

struct ima_digest_data {
	u8 algo;
	u8 length;
	union {
		struct {
			u8 unused;
			u8 type;
		} sha1;
		struct {
			u8 type;
			u8 algo;
		} ng;
		u8 data[2];
	} xattr;
	u8 digest[];
} __packed;

/*
 * Instead of wrapping the ima_digest_data struct inside a local structure
 * with the maximum hash size, define ima_max_digest_data struct.
 */
struct ima_max_digest_data {
	struct ima_digest_data hdr;
	u8 digest[HASH_MAX_DIGESTSIZE];
} __packed;

/*
 * signature header format v2 - for using with asymmetric keys
 *
 * The signature_v2_hdr struct includes a signature format version
 * to simplify defining new signature formats.
 *
 * signature format:
 * version 2: regular file data hash based signature
 * version 3: struct ima_file_id data based signature
 */
struct signature_v2_hdr {
	uint8_t type;		/* xattr type */
	uint8_t version;	/* signature format version */
	uint8_t	hash_algo;	/* Digest algorithm [enum hash_algo] */
	__be32 keyid;		/* IMA key identifier - not X509/PGP specific */
	__be16 sig_size;	/* signature size */
	uint8_t sig[];		/* signature payload */
} __packed;

/*
 * IMA signature version 3 disambiguates the data that is signed, by
 * indirectly signing the hash of the ima_file_id structure data,
 * containing either the fsverity_descriptor struct digest or, in the
 * future, the regular IMA file hash.
 *
 * (The hash of the ima_file_id structure is only of the portion used.)
 */
struct ima_file_id {
	__u8 hash_type;		/* xattr type [enum evm_ima_xattr_type] */
	__u8 hash_algorithm;	/* Digest algorithm [enum hash_algo] */
	__u8 hash[HASH_MAX_DIGESTSIZE];
} __packed;

/* integrity status of an inode in a namespace */
struct ns_status {
	struct list_head ns_next;	/* list connected to iint */
	unsigned long flags;		/* flags split with iint */
	unsigned long atomic_flags;	/* atomic_flags split with iint */
	unsigned long measured_pcrs;
	struct ima_namespace *ns;
#ifdef CONFIG_IMA_NS
	struct list_head ns_node;	/* list connected to ima_namespace */
	struct integrity_iint_cache *iint;
	struct inode *inode;
	ino_t i_ino;
	u32 i_generation;
#endif
	struct ima_digest_data *ima_hash;
};

static inline void ns_status_reset(struct ns_status *ns_status)
{
	ns_status->flags = 0;
	ns_status->atomic_flags = 0;
	ns_status->measured_pcrs = 0;
}

static inline void ns_status_init(struct ns_status *ns_status)
{
	INIT_LIST_HEAD(&ns_status->ns_next);
	ns_status_reset(ns_status);
}

/* integrity data associated with an inode */
struct integrity_iint_cache {
	struct mutex mutex;	/* protects: version, flags, digest */
	struct inode *inode;	/* back pointer to inode in question */
	u64 version;		/* track inode changes */
	unsigned long flags;	/* flags split with ns_status */
	unsigned long atomic_flags;	/* atomic_flags split with ns_status */
	enum integrity_status ima_file_status:4;
	enum integrity_status ima_mmap_status:4;
	enum integrity_status ima_bprm_status:4;
	enum integrity_status ima_read_status:4;
	enum integrity_status ima_creds_status:4;
	enum integrity_status evm_status:4;

	/*
	 * Lock and list of ns_status for files shared by different
	 * namespaces
	 */
	rwlock_t ns_list_lock;
	struct list_head ns_list;
#ifndef CONFIG_IMA_NS
	struct ns_status ns_status;
#endif
};

/* rbtree tree calls to lookup, insert, delete
 * integrity data associated with an inode.
 */
struct integrity_iint_cache *integrity_iint_find(struct inode *inode);
struct integrity_iint_cache *integrity_inode_get(struct inode *inode);

int integrity_kernel_read(struct file *file, loff_t offset,
			  void *addr, unsigned long count);

extern struct lsm_blob_sizes integrity_blob_sizes;

static inline struct integrity_iint_cache *
integrity_inode_get_iint(const struct inode *inode)
{
	struct integrity_iint_cache **iint_sec;

	iint_sec = inode->i_security + integrity_blob_sizes.lbs_inode;
	return *iint_sec;
}

static inline void integrity_inode_set_iint(const struct inode *inode,
					    struct integrity_iint_cache *iint)
{
	struct integrity_iint_cache **iint_sec;

	iint_sec = inode->i_security + integrity_blob_sizes.lbs_inode;
	*iint_sec = iint;
}

struct modsig;
struct integrity_namespace;

#ifdef CONFIG_IMA
void __init init_ima_lsm(void);
#else
static inline void __init init_ima_lsm(void)
{
}
#endif

#ifdef CONFIG_EVM
void __init init_evm_lsm(void);
#else
static inline void __init init_evm_lsm(void)
{
}
#endif

struct dentry *integrity_fs_init(struct integrity_namespace *ns,
				 struct dentry *root);
void integrity_fs_free(struct integrity_namespace *ns);

#ifdef CONFIG_INTEGRITY_SIGNATURE

int integrity_digsig_verify(struct integrity_namespace *ns,
			    const unsigned int id, const char *sig, int siglen,
			    const char *digest, int digestlen);
int integrity_modsig_verify(struct integrity_namespace *ns,
			    unsigned int id, const struct modsig *modsig);

int __init integrity_init_keyring(struct integrity_namespace *ns,
				  const unsigned int id);
int __init integrity_load_x509(struct integrity_namespace *ns,
			       const unsigned int id, const char *path);
int __init integrity_load_cert(struct integrity_namespace *ns,
			       const unsigned int id, const char *source,
			       const void *data, size_t len, key_perm_t perm);
#else

static inline int integrity_digsig_verify(struct integrity_namespace *ns,
					  const unsigned int id,
					  const char *sig, int siglen,
					  const char *digest, int digestlen)
{
	return -EOPNOTSUPP;
}

static inline int integrity_modsig_verify(struct integrity_namespace *ns,
					  unsigned int id,
					  const struct modsig *modsig)
{
	return -EOPNOTSUPP;
}

static inline int integrity_init_keyring(struct integrity_namespace *ns,
					 const unsigned int id)
{
	return 0;
}

static inline int __init integrity_load_cert(struct integrity_namespace *ns,
					     const unsigned int id,
					     const char *source,
					     const void *data, size_t len,
					     key_perm_t perm)
{
	return 0;
}
#endif /* CONFIG_INTEGRITY_SIGNATURE */

#ifdef CONFIG_INTEGRITY_ASYMMETRIC_KEYS
int asymmetric_verify(struct key *keyring, const char *sig,
		      int siglen, const char *data, int datalen);
int integrity_kernel_module_request(char *kmod_name);
#else
static inline int asymmetric_verify(struct key *keyring, const char *sig,
				    int siglen, const char *data, int datalen)
{
	return -EOPNOTSUPP;
}

static inline int integrity_kernel_module_request(char *kmod_name)
{
	return 0;
}
#endif

#ifdef CONFIG_IMA_APPRAISE_MODSIG
int ima_modsig_verify(struct key *keyring, const struct modsig *modsig);
#else
static inline int ima_modsig_verify(struct key *keyring,
				    const struct modsig *modsig)
{
	return -EOPNOTSUPP;
}
#endif

#ifdef CONFIG_IMA_LOAD_X509
void __init ima_load_x509(struct integrity_namespace *ns);
#else
static inline void ima_load_x509(struct integrity_namespace *ns)
{
}
#endif

#ifdef CONFIG_EVM_LOAD_X509
void __init evm_load_x509(struct integrity_namespace *ns);
#else
static inline void evm_load_x509(struct integrity_namespace *ns)
{
}
#endif

#ifdef CONFIG_INTEGRITY_AUDIT
/* declarations */
void integrity_audit_msg(int audit_msgno, struct inode *inode,
			 const unsigned char *fname, const char *op,
			 const char *cause, int result, int info);

void integrity_audit_message(int audit_msgno, struct inode *inode,
			     const unsigned char *fname, const char *op,
			     const char *cause, int result, int info,
			     int errno);

static inline struct audit_buffer *
integrity_audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type)
{
	return audit_log_start(ctx, gfp_mask, type);
}

#else
static inline void integrity_audit_msg(int audit_msgno, struct inode *inode,
				       const unsigned char *fname,
				       const char *op, const char *cause,
				       int result, int info)
{
}

static inline void integrity_audit_message(int audit_msgno,
					   struct inode *inode,
					   const unsigned char *fname,
					   const char *op, const char *cause,
					   int result, int info, int errno)
{
}

static inline struct audit_buffer *
integrity_audit_log_start(struct audit_context *ctx, gfp_t gfp_mask, int type)
{
	return NULL;
}

#endif

#ifdef CONFIG_INTEGRITY_PLATFORM_KEYRING
void __init add_to_platform_keyring(const char *source, const void *data,
				    size_t len);
#else
static inline void __init add_to_platform_keyring(const char *source,
						  const void *data, size_t len)
{
}
#endif

#ifdef CONFIG_INTEGRITY_MACHINE_KEYRING
void __init add_to_machine_keyring(const char *source, const void *data, size_t len);
bool __init imputed_trust_enabled(void);
#else
static inline void __init add_to_machine_keyring(const char *source,
						  const void *data, size_t len)
{
}

static inline bool __init imputed_trust_enabled(void)
{
	return false;
}
#endif
