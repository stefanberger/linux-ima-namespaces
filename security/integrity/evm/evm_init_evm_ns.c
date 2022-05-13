// SPDX-License-Identifier: GPL-2.0-only

#include <linux/evm.h>

#include "evm.h"

int evm_init_namespace(struct evm_namespace *ns,
		       struct integrity_namespace *integrity_ns)
{
	ns->integrity_ns = integrity_ns;
	ns->evmkey_len = MAX_KEY_SIZE;

	return 0;
}

int __init evm_init_ns(void)
{
	return evm_init_namespace(&init_evm_ns, &init_integrity_ns);
}

struct evm_namespace init_evm_ns = {
	.evm_ns_flags = BIT(EVM_NS_ACTIVE),
};
