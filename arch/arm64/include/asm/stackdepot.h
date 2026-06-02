/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_STACKDEPOT_H
#define __ASM_STACKDEPOT_H

#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <asm/sections.h>

#define STACK_DEPOT_ARM64_FRAME_LOW_MASK	0x00000000ffffffffUL
#define STACK_DEPOT_ARM64_FRAME_PREFIX_MASK	(~STACK_DEPOT_ARM64_FRAME_LOW_MASK)

/*
 * Modules are allocated inside a 2 GB relocation window containing the
 * kernel image, but stackdepot compression stores only the low 32 bits of
 * each frame. If that window crosses a 4 GB high-bit boundary, module text
 * may have the previous or next prefix even though it is still within
 * relocation range of _text.
 */
#define STACK_DEPOT_ARM64_PREV_PREFIX_ID	0
#define STACK_DEPOT_ARM64_TEXT_PREFIX_ID	1
#define STACK_DEPOT_ARM64_NEXT_PREFIX_ID	2

static inline unsigned long arch_stack_depot_frame_text_prefix(void)
{
	return (unsigned long)_text & STACK_DEPOT_ARM64_FRAME_PREFIX_MASK;
}

static inline bool arch_stack_depot_frame_prefix(u8 prefix_id,
						 unsigned long *prefix)
{
	unsigned long text_prefix = arch_stack_depot_frame_text_prefix();

	switch (prefix_id) {
	case STACK_DEPOT_ARM64_PREV_PREFIX_ID:
		/* Avoid underflow and the zero prefix; such frames stay raw. */
		if (text_prefix <= SZ_4G)
			return false;
		*prefix = text_prefix - SZ_4G;
		return true;
	case STACK_DEPOT_ARM64_TEXT_PREFIX_ID:
		*prefix = text_prefix;
		return true;
	case STACK_DEPOT_ARM64_NEXT_PREFIX_ID:
		if (text_prefix > ULONG_MAX - SZ_4G)
			return false;
		*prefix = text_prefix + SZ_4G;
		return true;
	default:
		return false;
	}
}

static inline bool arch_stack_depot_frame_try_compress(unsigned long frame,
						       u8 *prefix_id, u32 *low)
{
	unsigned long prefix = frame & STACK_DEPOT_ARM64_FRAME_PREFIX_MASK;
	unsigned long candidate;
	u8 i;

	if (!prefix_id || !low)
		return false;

	for (i = STACK_DEPOT_ARM64_PREV_PREFIX_ID;
	     i <= STACK_DEPOT_ARM64_NEXT_PREFIX_ID; i++) {
		if (!arch_stack_depot_frame_prefix(i, &candidate))
			continue;
		if (prefix != candidate)
			continue;

		*prefix_id = i;
		*low = (u32)frame;
		return true;
	}

	return false;
}

static inline bool arch_stack_depot_frame_decompress(u8 prefix_id, u32 low,
						     unsigned long *frame)
{
	unsigned long prefix;

	if (!frame)
		return false;

	if (!arch_stack_depot_frame_prefix(prefix_id, &prefix))
		return false;

	*frame = prefix | low;
	return true;
}

#endif /* __ASM_STACKDEPOT_H */
