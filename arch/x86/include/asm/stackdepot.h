/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_STACKDEPOT_H
#define _ASM_X86_STACKDEPOT_H

#include <linux/types.h>

#ifdef CONFIG_X86_64
#define STACK_DEPOT_X86_64_FRAME_PREFIX	0xffffffff00000000UL
#define STACK_DEPOT_X86_64_FRAME_LOW_MASK	0x00000000ffffffffUL

static inline bool arch_stack_depot_frame_try_compress(unsigned long frame,
						       u8 *prefix_id, u32 *low)
{
	if ((frame & ~STACK_DEPOT_X86_64_FRAME_LOW_MASK) !=
	    STACK_DEPOT_X86_64_FRAME_PREFIX)
		return false;

	*prefix_id = 0;
	*low = (u32)frame;
	return true;
}

static inline bool arch_stack_depot_frame_decompress(u8 prefix_id, u32 low,
						     unsigned long *frame)
{
	if (prefix_id)
		return false;

	*frame = STACK_DEPOT_X86_64_FRAME_PREFIX | low;
	return true;
}

#else
#include <asm-generic/stackdepot.h>
#endif /* CONFIG_X86_64 */

#endif /* _ASM_X86_STACKDEPOT_H */
