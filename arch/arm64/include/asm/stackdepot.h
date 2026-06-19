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
static inline bool
arch_stack_depot_frame_try_compress(unsigned long frame, u32 *low)
{
	long offset;

	if (!low)
		return false;

	offset = (long)frame - (long)_text;
	if (offset < S32_MIN || offset > S32_MAX)
		return false;

	*low = (u32)(s32)offset;
	return true;
}

static inline bool
arch_stack_depot_frame_decompress(u32 low, unsigned long *frame)
{
	if (!frame)
		return false;

	*frame = (unsigned long)((long)_text + (s32)low);
	return true;
}

#endif /* __ASM_STACKDEPOT_H */
