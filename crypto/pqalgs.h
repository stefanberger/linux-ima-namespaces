// SPDX-License-Identifier: Apache-2.0

#if !defined(PQALGS_H__)
#define  PQALGS_H__  1

/* defining USE_STATIC_MLCA keeps functions internal to build unit */

#ifdef __cplusplus
extern "C" {
#endif

/*--------------------------------------
 * Verify signature: validates signature (sig, sbytes) corresponding to
 * (msg, mbytes), using the public key (pub, pbytes).
 *
 * Returns >0  if signature has been verified
 *         0   if signature is invalid
 *         <0  other errors, such as invalid key or mode
 *
 * Public key has been returned by an earlier call to pqcr_generate().
 *
 * (algid, ibytes)  selects the key algorithm.  If (NULL, 0), a
 * key(type)-specific default is selected; see algorithm-specific definitions.
 */
#if defined(USE_STATIC_MLCA)
static
#endif
/**/
int mlca_verify(const unsigned char *sig,   size_t sbytes,
                const unsigned char *msg,   size_t mbytes,
                const unsigned char *pub,   size_t pbytes,
                const unsigned char *algid, size_t ibytes) ;


/*-----  extension notes  ----------------------------------------------------
 * As an alternative to object identifiers (OIDs), an append-only
 * list for algorithm/size/etc. selectors have been defined; see
 * MLCA_ID_t for a full list. These constants must be supplied as
 * (NULL, ...constant...) instead of a non-NULL OID, or (NULL, 0)
 * where the latter implies defaults.
 *
 * Implementations MAY use handles instead of raw key structures;
 * the API is not expected to change for such indirection-addressed
 * providers.
 */

typedef enum {
		/* all reserved values are >0, < 0x1000000
		 * mapped values have some internal structure, do
		 * not change them
		 */

		/* round 2 Dilithium, NIST strength categories,
		 * implies IBM-specified private+public key formats when
 		 * used in serialization context.
		 */
	MLCA_ID_DIL3_R2 = 0x0105,
	MLCA_ID_DIL4_R2 = 0x0106,
	MLCA_ID_DIL5_R2 = 0x0108,

		/* round 2 Dilithium, NIST strength categories,
		 * implies ref.impl-derived, 'raw' private+public keys when
 		 * used in serialization context, such as generated/used
		 * by liboqs.
		 *
		 * when used as key(generate) or signature type,
		 * DIL<n>_R2_RAW is identical to the corresponding DIL<n>_R2.
		 */
	MLCA_ID_DIL3_R2_RAW = 0x0205,
	MLCA_ID_DIL4_R2_RAW = 0x0206,
	MLCA_ID_DIL5_R2_RAW = 0x0208,

		/* round 3 Dilithium, NIST strength categories,
		 * compressed round 3 signatures
		 *
		 * when used as key type, DIL<n>_R2 is identical
		 * to the corresponding DIL<n>_R2.
		 */
	MLCA_ID_DIL2_R3 = 0x0344,
	MLCA_ID_DIL3_R3 = 0x0365,
	MLCA_ID_DIL5_R3 = 0x0387,

	MLCA_ID_DIL_MLDSA_44 = 0x0444,
    MLCA_ID_DIL_MLDSA_65 = 0x0465,
    MLCA_ID_DIL_MLDSA_87 = 0x0487,

		/* round 2 Kyber, NIST strength categories,
		 * implies IBM-specified private+public key formats when
 		 * used in serialization context.
		 */
	MLCA_ID_KYB3_R2 = 0x0503,
	MLCA_ID_KYB4_R2 = 0x0504,

		/* round 3 Kyber, NIST strength categories, 2020-10-01 update,
		 * implies IBM-specified private+public key formats when
 		 * used in serialization context.
		 */
	MLCA_ID_KYB3_R3 = 0x0803,
	MLCA_ID_KYB4_R3 = 0x0804,

    MLCA_ID_KYB_MLKEM_768  = 0x0903,
    MLCA_ID_KYB_MLKEM_1024 = 0x0904,


		/* portability note: make sure no comma after last entries
		 */

	MLCA_ID_MAX = MLCA_ID_KYB_MLKEM_1024
} MLCA_ID_t ;


/* additional bits which may be combined with MLCA_ID_t constants
 */
typedef enum {
	MLCA_IDP_PUBLIC = 0x1000000
} MLCA_IDplus_t ;


/*--------------------------------------
 * features controlling key transport
 */
typedef enum {
	MLCA_KEYTR_NOPUBLIC = 1,     /* omit public-key field from prv.key */
	MLCA_KEYTR_MINIMAL  = 2      /* use maximally-compressed form of key */
} MLCA_KeyTransp_t ;


/*-----  limits  ---------------------*/
/* fits any supported Kyber priv.key or public key [raw, not wire-formatted] */
#define KYB_PRV_MAX_BYTES        3168
#define KYB_PUB_MAX_BYTES        1568
#define KYB_CIPHERTXT_MAX_BYTES  1568

#ifdef MLCA_MINIMAL
typedef enum {
	MLCA_OK          =   0,
	MLCA_EPARAM      =  -1,  /* missing/NULL param; non-NULL expected */
	MLCA_ESTRENGTH   =  -2,  /* parameters strength/policy-restricted */
	MLCA_ESTRUCT     =  -3,  /* key(structure) is not recognized */
	MLCA_EKEYTYPE    =  -4,  /* object ID/key-object type not recognized */
	MLCA_EKEYMODE    =  -5,  /* key incompatible with requested function */
	MLCA_EKEYSIZE    =  -6,  /* invalid input-key size (non-specific) */
	MLCA_EPUBKEYSIZE =  -7,  /* invalid input-key size (public key) */
	MLCA_EMODE       =  -8,  /* operation incompatible with requested
	                            function/mode */
	MLCA_ETOOSMALL   =  -9,  /* insufficient output buffer */
	MLCA_ERNG        = -10,  /* call to random-number generator failed */
	MLCA_EINTERN     = -11,  /* CSP internal consistency error */
	MLCA_EMISSING    = -12,  /* requested key component is not present */
	MLCA_ENSUPPORT   = -13,  /* requested operation(OID?) not supported */
    MLCA_EMEM        = -14,  /* memory operation failed */
    MLCA_GEN         = -15,  /* MLCA generic error */
} MLCA_RC;
#else
#include <mlca2_int.h>
#endif

#define FLAGS_KEY2WIRE_DEFAULT 0
#define FLAGS_KEY2WIRE_GETPUB 1
#define FLAGS_KEY2WIRE_GETPUBHASH 2

/* see also: crystals-oids.h */

#ifdef __cplusplus
}
#endif     /* cplusplus */
#endif     /* PQALGS_H__ */
