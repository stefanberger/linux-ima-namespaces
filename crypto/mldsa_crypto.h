
#include <linux/types.h>
#include <linux/string.h>

#include "keccak.h"

#define NO_CRYSTALS_KEX
#define NO_CRYSTALS_CIP
#define MLCA_MINIMAL

#define DIL_MLDSA_44_PUB_BYTES ((size_t)1312)
#define DIL_MLDSA_65_PUB_BYTES ((size_t)1952)
#define DIL_MLDSA_87_PUB_BYTES ((size_t)2592)

int mlca_verify(const unsigned char *sig, size_t sbytes,
                const unsigned char *msg, size_t mbytes, const unsigned char *pub,
                size_t pbytes, const unsigned char *algid, size_t ibytes);
