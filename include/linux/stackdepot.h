/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Stack depot - a stack trace storage that avoids duplication.
 *
 * Stack depot is intended to be used by subsystems that need to store and
 * later retrieve many potentially duplicated stack traces without wasting
 * memory.
 *
 * For example, KASAN needs to save allocation and free stack traces for each
 * object. Storing two stack traces per object requires a lot of memory (e.g.
 * SLUB_DEBUG needs 256 bytes per object for that). Since allocation and free
 * stack traces often repeat, using stack depot allows to save about 100x space.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on the code by Dmitry Chernenkov.
 */

#ifndef _LINUX_STACKDEPOT_H
#define _LINUX_STACKDEPOT_H

#include <linux/gfp.h>

typedef u32 depot_stack_handle_t;

/*
 * Number of bits in the handle that stack depot doesn't use. Users may store
 * information in them via stack_depot_set/get_extra_bits.
 */
#define STACK_DEPOT_EXTRA_BITS 5

#define DEPOT_HANDLE_BITS (sizeof(depot_stack_handle_t) * 8)

#define DEPOT_POOL_ORDER 2 /* Pool size order, 4 pages */
#define DEPOT_POOL_SIZE (1LL << (PAGE_SHIFT + DEPOT_POOL_ORDER))
#define DEPOT_STACK_ALIGN 4
#define DEPOT_OFFSET_BITS (DEPOT_POOL_ORDER + PAGE_SHIFT - DEPOT_STACK_ALIGN)
#define DEPOT_POOL_INDEX_BITS (DEPOT_HANDLE_BITS - DEPOT_OFFSET_BITS - \
			       STACK_DEPOT_EXTRA_BITS)

typedef u32 depot_flags_t;

/*
 * Flags that can be passed to stack_depot_save_flags(); see the comment next
 * to its declaration for more details.
 */
#define STACK_DEPOT_FLAG_CAN_ALLOC	((depot_flags_t)0x0001)
#define STACK_DEPOT_FLAG_GET		((depot_flags_t)0x0002)

#define STACK_DEPOT_FLAGS_NUM	2
#define STACK_DEPOT_FLAGS_MASK	((depot_flags_t)((1 << STACK_DEPOT_FLAGS_NUM) - 1))

enum stack_depot_frame_mode {
	STACK_DEPOT_FRAME_RAW,
	STACK_DEPOT_FRAME_COMPRESSED,
};

struct stack_depot_frame_run {
	enum stack_depot_frame_mode mode;
	u8 prefix_id;
	unsigned int nr_entries;
	size_t bytes;
};

/*
 * Using stack depot requires its initialization, which can be done in 3 ways:
 *
 * 1. Selecting CONFIG_STACKDEPOT_ALWAYS_INIT. This option is suitable in
 *    scenarios where it's known at compile time that stack depot will be used.
 *    Enabling this config makes the kernel initialize stack depot in mm_init().
 *
 * 2. Calling stack_depot_request_early_init() during early boot, before
 *    stack_depot_early_init() in mm_init() completes. For example, this can
 *    be done when evaluating kernel boot parameters.
 *
 * 3. Calling stack_depot_init(). Possible after boot is complete. This option
 *    is recommended for modules initialized later in the boot process, after
 *    mm_init() completes.
 *
 * stack_depot_init() and stack_depot_request_early_init() can be called
 * regardless of whether CONFIG_STACKDEPOT is enabled and are no-op when this
 * config is disabled. The save/fetch/print stack depot functions can only be
 * called from the code that makes sure CONFIG_STACKDEPOT is enabled _and_
 * initializes stack depot via one of the ways listed above.
 */
#ifdef CONFIG_STACKDEPOT
int stack_depot_init(void);

void __init stack_depot_request_early_init(void);

/* Must be only called from mm_init(). */
int __init stack_depot_early_init(void);
#else
static inline int stack_depot_init(void) { return 0; }

static inline void stack_depot_request_early_init(void) { }

static inline int stack_depot_early_init(void)	{ return 0; }
#endif

/**
 * stack_depot_save_flags - Save a stack trace to stack depot
 *
 * @entries:		Pointer to the stack trace
 * @nr_entries:		Number of frames in the stack
 * @alloc_flags:	Allocation GFP flags
 * @depot_flags:	Stack depot flags
 *
 * Saves a stack trace from @entries array of size @nr_entries.
 *
 * If STACK_DEPOT_FLAG_CAN_ALLOC is set in @depot_flags, stack depot can
 * replenish the stack pools in case no space is left (allocates using GFP
 * flags of @alloc_flags). Otherwise, stack depot avoids any allocations and
 * fails if no space is left to store the stack trace.
 *
 * If STACK_DEPOT_FLAG_GET is set in @depot_flags, stack depot will increment
 * the refcount on the saved stack trace if it already exists in stack depot.
 * Users of this flag must also call stack_depot_put() when keeping the stack
 * trace is no longer required to avoid overflowing the refcount.
 *
 * If the provided stack trace comes from the interrupt context, only the part
 * up to the interrupt entry is saved.
 *
 * Context: Any context, but unsetting STACK_DEPOT_FLAG_CAN_ALLOC is required if
 *          alloc_pages() cannot be used from the current context. Currently
 *          this is the case for contexts where neither %GFP_ATOMIC nor
 *          %GFP_NOWAIT can be used (NMI, raw_spin_lock).
 *
 * Return: Handle of the stack struct stored in depot, 0 on failure
 */
depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
					    unsigned int nr_entries,
					    gfp_t alloc_flags,
					    depot_flags_t depot_flags);

/**
 * stack_depot_save - Save a stack trace to stack depot
 *
 * @entries:		Pointer to the stack trace
 * @nr_entries:		Number of frames in the stack
 * @alloc_flags:	Allocation GFP flags
 *
 * Does not increment the refcount on the saved stack trace; see
 * stack_depot_save_flags() for more details.
 *
 * Context: Contexts where allocations via alloc_pages() are allowed;
 *          see stack_depot_save_flags() for more details.
 *
 * Return: Handle of the stack trace stored in depot, 0 on failure
 */
depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries, gfp_t alloc_flags);

/**
 * __stack_depot_get_count - Get a counted stack record count
 *
 * @handle: Stack depot handle
 * @count:  Pointer to store the count
 *
 * This function is only for internal purposes.
 * The returned count is an unsynchronized snapshot for diagnostics.
 *
 * Return: true on success, false if @handle is invalid, @count is NULL, or the
 * stack record is not in counted mode.
 */
bool __stack_depot_get_count(depot_stack_handle_t handle, unsigned int *count);

/**
 * __stack_depot_set_count - Set a stack record count
 *
 * @handle: Stack depot handle
 * @count: Count to set
 *
 * This function is only for internal purposes.
 * If @count is 0 or greater than %INT_MAX, this function is a
 * no-op.
 * Callers that use this to switch a saturated record to counted mode must
 * separately make the record discoverable by their own tracking structure.
 * Callers must have exclusive access to the stack record count.
 */
void __stack_depot_set_count(depot_stack_handle_t handle, unsigned int count);

/**
 * __stack_depot_inc_count - Increment a stack record count
 *
 * @handle: Stack depot handle
 * @count: Count to add
 *
 * This function is only for internal purposes.
 * If @count is 0, this function is a no-op. Otherwise @count must be less
 * than or equal to %INT_MAX - 1.
 *
 * Persistent stack records start with refcount set to %REFCOUNT_SATURATED. If
 * this helper switches a saturated record to counted mode, it stores @count + 1.
 * For records already in counted mode, cumulative overflow is handled by the
 * underlying refcount_add() saturation semantics; whether that also emits a
 * warning depends on the refcount configuration. If such an overflow happens,
 * later count get/decrement attempts treat the record as no longer counted and
 * fail closed.
 * Callers must ensure @handle remains valid for the duration of this call.
 *
 * Return: true if this call switched the record from saturated to counted,
 * false otherwise.
 */
bool __stack_depot_inc_count(depot_stack_handle_t handle, unsigned int count);

/**
 * __stack_depot_dec_count_and_test - Decrement a stack record count
 *
 * @handle: Stack depot handle
 * @count: Count to subtract
 *
 * This function is only for internal purposes.
 * @count must be greater than 0 and less than or equal to %INT_MAX - 1.
 *
 * Return: true if the resulting count is 0, false if the resulting count is
 * non-zero, @handle is invalid, the stack record is not in counted mode, or
 * @count is greater than the current count. Saturated persistent records are
 * not in counted mode and fail closed without changing the record. Underflow
 * attempts warn and leave the count unchanged.
 */
bool __stack_depot_dec_count_and_test(depot_stack_handle_t handle,
				      unsigned int count);

/**
 * __stack_depot_frame_try_compress - Try to compress a stack frame
 *
 * @frame: Stack frame address
 * @prefix_id: Storage for the architecture prefix id
 * @low: Storage for the compressed low bits
 *
 * This function is only for internal purposes. The generic implementation is a
 * raw fallback and never compresses.
 * @prefix_id and @low must be non-NULL.
 *
 * Return: true if @frame was compressed, false otherwise.
 */
bool __stack_depot_frame_try_compress(unsigned long frame, u8 *prefix_id,
				      u32 *low);

/**
 * __stack_depot_frame_decompress - Decompress a stack frame
 *
 * @prefix_id: Architecture prefix id returned by compression
 * @low: Compressed low bits returned by compression
 * @frame: Storage for the decompressed frame
 *
 * This function is only for internal purposes. The generic raw fallback has no
 * compressed representation to decode.
 * @frame must be non-NULL.
 *
 * Return: true if @frame was decompressed, false otherwise.
 */
bool __stack_depot_frame_decompress(u8 prefix_id, u32 low,
				    unsigned long *frame);

/**
 * __stack_depot_frame_run_init - Describe a homogeneous stack frame run
 *
 * @entries: Stack frames that start the run
 * @nr_entries: Number of frames available in @entries
 * @run: Storage for the resulting run description
 *
 * This function is only for internal purposes. It describes the longest prefix
 * of @entries that can be stored with one payload format: raw frames, or low
 * bits for frames that all share one architecture prefix id. It does not write
 * frame payload data; callers that need payload storage must call
 * __stack_depot_frame_run_write().
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int __stack_depot_frame_run_init(const unsigned long *entries,
				 unsigned int nr_entries,
				 struct stack_depot_frame_run *run);

/**
 * __stack_depot_frame_run_write - Write a stack frame run payload
 *
 * @run: Run description returned by __stack_depot_frame_run_init()
 * @entries: Stack frames to encode
 * @dst: Payload buffer to write
 * @dst_size: Size of @dst in bytes
 * @scratch: Scratch buffer for compressed frame payloads
 * @nr_scratch: Number of 32-bit entries that fit in @scratch
 *
 * This function is only for internal purposes. It does not write partial
 * compressed payloads: if any frame does not match @run, @dst is unchanged.
 * Compressed runs require @scratch to hold at least @run->nr_entries entries;
 * raw runs do not use @scratch. @dst must not overlap @entries.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int __stack_depot_frame_run_write(const struct stack_depot_frame_run *run,
				  const unsigned long *entries, void *dst,
				  size_t dst_size, u32 *scratch,
				  unsigned int nr_scratch);

/**
 * __stack_depot_frame_run_read - Read a stack frame run payload
 *
 * @run: Run description for the payload
 * @src: Payload buffer to read
 * @src_size: Size of @src in bytes
 * @entries: Storage for decoded stack frames
 * @max_entries: Number of frames that fit in @entries
 * @scratch: Scratch buffer for decoded compressed frames
 * @nr_scratch: Number of frames that fit in @scratch
 *
 * This function is only for internal purposes. It does not write partial
 * compressed output: if any frame cannot be decoded, @entries is unchanged.
 * Compressed runs require @scratch to hold at least @run->nr_entries entries;
 * raw runs do not use @scratch. For compressed runs, @entries and @scratch
 * must not overlap.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int __stack_depot_frame_run_read(const struct stack_depot_frame_run *run,
				 const void *src, size_t src_size,
				 unsigned long *entries, unsigned int max_entries,
				 unsigned long *scratch,
				 unsigned int nr_scratch);

/**
 * __stack_depot_trie_node_size - Get storage size for a trie node
 *
 * @run: Frame run to store in the node
 *
 * This function is only for internal purposes.
 *
 * Return: Aligned node storage size, 0 on invalid input.
 */
size_t __stack_depot_trie_node_size(const struct stack_depot_frame_run *run);

/**
 * __stack_depot_trie_node_init - Initialize a trie node in caller storage
 *
 * @storage: Node storage to initialize
 * @storage_size: Size of @storage in bytes
 * @parent: Parent node or NULL for a root node
 * @leaf_id: Non-zero id when this node terminates a stored stack
 * @entries: Homogeneous frame run to store in this node
 * @nr_entries: Number of frames in @entries
 * @scratch: Scratch buffer for compressed frame payloads
 * @nr_scratch: Number of 32-bit entries that fit in @scratch
 *
 * This function is only for internal purposes. It does not publish @storage;
 * all @entries must fit in one raw or same-prefix compressed frame run. Callers
 * remain responsible for lifetime and visibility. Callers must discard @storage
 * unless this function returns 0.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int __stack_depot_trie_node_init(void *storage, size_t storage_size,
				 const void *parent, u32 leaf_id,
				 const unsigned long *entries,
				 unsigned int nr_entries, u32 *scratch,
				 unsigned int nr_scratch);

/**
 * __stack_depot_trie_node_match - Match entries against one trie node
 *
 * @node: Trie node to compare
 * @entries: Stack frames to match from the start of @node
 * @nr_entries: Number of frames available in @entries
 *
 * This function is only for internal purposes. It compares @entries against the
 * decoded frame run stored in @node and does not walk parent or child links.
 *
 * Return: Number of matching frames, up to the smaller of the node run length
 * and @nr_entries. Returns 0 on invalid input or a first-frame mismatch.
 */
unsigned int __stack_depot_trie_node_match(const void *node,
					   const unsigned long *entries,
					   unsigned int nr_entries);

/**
 * __stack_depot_trie_fetch_into - Materialize a trie parent chain
 *
 * @leaf: Leaf node to materialize from
 * @entries: Caller-owned output buffer
 * @max_entries: Number of frames that fit in @entries
 * @scratch: Caller-owned scratch buffer for staged output
 * @nr_scratch: Number of frames that fit in @scratch
 *
 * This function is only for internal purposes. It stages the full stack into
 * @scratch first, so failures do not partially write @entries. @scratch is
 * caller-owned temporary storage and may be modified on failure.
 *
 * Return: Number of frames copied, 0 on invalid input or too-small buffers.
 */
unsigned int
__stack_depot_trie_fetch_into(const void *leaf, unsigned long *entries,
			      unsigned int max_entries, unsigned long *scratch,
			      unsigned int nr_scratch);

/**
 * __stack_depot_trie_child_array_size - Get storage size for child pointers
 *
 * @nr_children: Number of child pointers stored in the array
 *
 * This function is only for internal purposes.
 *
 * Return: Aligned child-array storage size, 0 on overflow.
 */
size_t __stack_depot_trie_child_array_size(unsigned int nr_children);

/**
 * __stack_depot_trie_child_array_init - Initialize sorted child storage
 *
 * @storage: Child-array storage to initialize
 * @storage_size: Size of @storage in bytes
 * @children: Children sorted by first decoded frame
 * @nr_children: Number of child pointers in @children
 *
 * This function is only for internal purposes. It does not publish @storage;
 * callers remain responsible for lifetime and visibility. Callers must discard
 * @storage unless this function returns 0.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int
__stack_depot_trie_child_array_init(void *storage, size_t storage_size,
				    const void * const *children,
				    unsigned int nr_children);

/**
 * __stack_depot_trie_child_array_find - Find a child by first frame
 *
 * @storage: Child-array storage initialized by child_array_init/insert
 * @frame: First decoded frame to search for
 *
 * This function is only for internal purposes.
 *
 * Return: Child pointer if found, NULL otherwise.
 */
const void *
__stack_depot_trie_child_array_find(const void *storage, unsigned long frame);

/**
 * __stack_depot_trie_child_array_insert - Build replacement child storage
 *
 * @old_storage: Existing sorted child array, or NULL
 * @child: Child node to insert
 * @new_storage: Replacement child-array storage to initialize
 * @new_storage_size: Size of @new_storage in bytes
 *
 * This function is only for internal purposes. It builds a new sorted child
 * array and rejects duplicate first-frame keys and in-place updates.
 *
 * Return: 0 on success, -EINVAL on invalid input.
 */
int
__stack_depot_trie_child_array_insert(const void *old_storage, const void *child,
				      void *new_storage, size_t new_storage_size);

/**
 * stack_depot_fetch - Fetch a stack trace from stack depot
 *
 * @handle:	Stack depot handle returned from stack_depot_save()
 * @entries:	Pointer to store the address of the stack trace
 *
 * Return: Number of frames for the fetched stack
 */
unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries);

/**
 * stack_depot_fetch_into - Fetch a stack trace into caller-owned storage
 *
 * @handle:	Stack depot handle returned from stack_depot_save()
 * @entries:	Caller-owned buffer to copy the stack trace into
 * @max_entries:	Number of frames that fit in @entries
 *
 * Copies the stored frames into caller-owned @entries. If fewer frames are
 * stored than @max_entries, only the stored frames are written and their count
 * is returned. If more frames are stored than @max_entries, the copy is skipped
 * entirely and 0 is returned.
 *
 * Callers must ensure @handle remains valid for the duration of this call.
 * Persistent handles saved without %STACK_DEPOT_FLAG_GET require no extra
 * reference; handles saved with %STACK_DEPOT_FLAG_GET require a held reference.
 * Callers must not call stack_depot_put() on persistent handles.
 * Racing this helper with stack_depot_put() on the same handle is invalid.
 *
 * Return: Number of frames copied, 0 if @entries is NULL, @max_entries is 0,
 * @handle is 0 or invalid, stack depot is disabled, or @max_entries is less
 * than the number of stored frames.
 * An invalid or post-put @handle may also trigger a warning from the underlying
 * stack_depot_fetch() call.
 */
unsigned int stack_depot_fetch_into(depot_stack_handle_t handle,
				    unsigned long *entries,
				    unsigned int max_entries);

/**
 * stack_depot_print - Print a stack trace from stack depot
 *
 * @stack:	Stack depot handle returned from stack_depot_save()
 */
void stack_depot_print(depot_stack_handle_t stack);

/**
 * stack_depot_snprint - Print a stack trace from stack depot into a buffer
 *
 * @handle:	Stack depot handle returned from stack_depot_save()
 * @buf:	Pointer to the print buffer
 * @size:	Size of the print buffer
 * @spaces:	Number of leading spaces to print
 *
 * Return:	Number of bytes printed
 */
int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
		       int spaces);

/**
 * stack_depot_put - Drop a reference to a stack trace from stack depot
 *
 * @handle:	Stack depot handle returned from stack_depot_save()
 *
 * The stack trace is evicted from stack depot once all references to it have
 * been dropped (once the number of stack_depot_evict() calls matches the
 * number of stack_depot_save_flags() calls with STACK_DEPOT_FLAG_GET set for
 * this stack trace).
 */
void stack_depot_put(depot_stack_handle_t handle);

/**
 * stack_depot_set_extra_bits - Set extra bits in a stack depot handle
 *
 * @handle:	Stack depot handle returned from stack_depot_save()
 * @extra_bits:	Value to set the extra bits
 *
 * Return: Stack depot handle with extra bits set
 *
 * Stack depot handles have a few unused bits, which can be used for storing
 * user-specific information. These bits are transparent to the stack depot.
 */
depot_stack_handle_t __must_check stack_depot_set_extra_bits(
			depot_stack_handle_t handle, unsigned int extra_bits);

/**
 * stack_depot_get_extra_bits - Retrieve extra bits from a stack depot handle
 *
 * @handle:	Stack depot handle with extra bits saved
 *
 * Return: Extra bits retrieved from the stack depot handle
 */
unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle);

#endif
