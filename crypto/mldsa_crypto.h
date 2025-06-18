/* SPDX-License-Identifier: GPL-2.0+ */
#ifndef _CRYPTO_MLDSA_CRYPTO_H
#define _CRYPTO_MLDSA_CRYPTO_H

#include <linux/types.h>

/* sizes of public keys */
#define MLDSA_44_PUB_BYTES ((size_t)1312)
#define MLDSA_65_PUB_BYTES ((size_t)1952)
#define MLDSA_87_PUB_BYTES ((size_t)2592)

/* maximum signature size */
#define MLDSA_MAX_SIG_SIZE 4627 /* mldsa-87 */

int mldsa_verify_internal(const unsigned char *sig, size_t sbytes,
			  const unsigned char *msg, size_t mbytes,
			  const unsigned char *pub, size_t pbytes,
			  const unsigned char *domsep, size_t domseplen,
			  const unsigned char *ctx, size_t cbytes);

#endif
