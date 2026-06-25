/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_STACKDEPOT_H
#define __ASM_STACKDEPOT_H

#include <linux/types.h>
#include <linux/limits.h>
#include <asm/sections.h>

/*
 * Modules are allocated inside a 2 GB relocation window containing the
 * kernel image. Store a signed 32-bit offset from _text so compression is
 * independent of 4 GB high-bit boundaries crossed by that window.
 */
static inline unsigned long arch_stack_depot_frame_from_low(u32 low)
{
	long offset;

	offset = (s32)low;
	if (offset < 0)
		return (unsigned long)_text - (unsigned long)(-offset);
	return (unsigned long)_text + (unsigned long)offset;
}

static inline bool
arch_stack_depot_frame_try_compress(unsigned long frame, u32 *low)
{
	u32 candidate;

	candidate = (u32)(frame - (unsigned long)_text);
	if (arch_stack_depot_frame_from_low(candidate) != frame)
		return false;

	*low = candidate;
	return true;
}

static inline bool
arch_stack_depot_frame_decompress(u32 low, unsigned long *frame)
{
	*frame = arch_stack_depot_frame_from_low(low);
	return true;
}

#endif /* __ASM_STACKDEPOT_H */
