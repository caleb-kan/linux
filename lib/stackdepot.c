// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack depot - a stack trace storage that avoids duplication.
 *
 * Internally, stack depot maintains a hash table of unique stacktraces. The
 * stack traces themselves are stored contiguously one after another in a set
 * of separate page allocations.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on the code by Dmitry Chernenkov.
 */

#define pr_fmt(fmt) "stackdepot: " fmt

#include <linux/bitmap.h>
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/jump_label.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/kmsan.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/poison.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/kasan-enabled.h>

#include <asm/stackdepot.h>

#include "stackdepot_internal.h"

/*
 * The pool_index is offset by 1 so the first record does not have a 0 handle.
 */
static unsigned int stack_max_pools __read_mostly =
	MIN((1LL << DEPOT_POOL_INDEX_BITS) - 1, 8192);

static bool stack_depot_disabled;
static bool __stack_depot_early_init_requested __initdata =
	IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
static bool __stack_depot_early_init_passed __initdata;
static DEFINE_STATIC_KEY_FALSE(stack_depot_trie_enabled);
static bool stack_depot_trie_enabled_param;
static struct stack_depot_trie_root stack_depot_trie_root;
static struct stack_depot_trie_alloc_workspace *stack_depot_trie_workspace;
static DEFINE_RAW_SPINLOCK(stack_depot_trie_workspace_lock);
static bool stack_depot_trie_ready;

bool __stack_depot_trie_enabled(void)
{
	return static_branch_unlikely(&stack_depot_trie_enabled);
}

void __stack_depot_trie_set_enabled(bool enabled)
{
	if (READ_ONCE(stack_depot_trie_enabled_param) == enabled)
		return;

	WRITE_ONCE(stack_depot_trie_enabled_param, enabled);
	if (enabled)
		static_branch_enable(&stack_depot_trie_enabled);
	else
		static_branch_disable(&stack_depot_trie_enabled);
}

static int stack_depot_trie_enabled_param_set(const char *val,
					      const struct kernel_param *kp)
{
	struct kernel_param tmp = *kp;
	bool enabled;
	int ret;

	tmp.arg = &enabled;
	ret = param_set_bool(val, &tmp);
	if (ret)
		return ret;

	__stack_depot_trie_set_enabled(enabled);
	return 0;
}

static int stack_depot_trie_enabled_param_get(char *buffer,
					      const struct kernel_param *kp)
{
	struct kernel_param tmp = *kp;
	bool enabled = READ_ONCE(*(bool *)kp->arg);

	tmp.arg = &enabled;
	return param_get_bool(buffer, &tmp);
}

static const struct kernel_param_ops stack_depot_trie_enabled_param_ops = {
	/* param_set_bool() treats a missing value as true. */
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = stack_depot_trie_enabled_param_set,
	.get = stack_depot_trie_enabled_param_get,
};
module_param_cb(trie_enabled, &stack_depot_trie_enabled_param_ops,
		&stack_depot_trie_enabled_param, 0644);
MODULE_PARM_DESC(trie_enabled, "Enable stack depot trie storage");

/* Use one hash table bucket per 16 KB of memory. */
#define STACK_HASH_TABLE_SCALE 14
/* Limit the number of buckets between 4K and 1M. */
#define STACK_BUCKET_NUMBER_ORDER_MIN 12
#define STACK_BUCKET_NUMBER_ORDER_MAX 20
/* Initial seed for jhash2. */
#define STACK_HASH_SEED 0x9747b28c

/* Compact structure that stores a reference to a stack. */
union handle_parts {
	depot_stack_handle_t handle;
	struct {
		u32 pool_index_plus_1	: DEPOT_POOL_INDEX_BITS;
		u32 offset		: DEPOT_OFFSET_BITS;
		u32 extra		: STACK_DEPOT_EXTRA_BITS;
	};
};

struct stack_record {
	struct list_head hash_list;	/* Links in the hash table */
	u32 hash;			/* Hash in hash table */
	u32 size;			/* Number of stored frames */
	union handle_parts handle;	/* Constant after initialization */
	refcount_t count;
	union {
		unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];	/* Frames */
		struct {
			/*
			 * An important invariant of the implementation is to
			 * only place a stack record onto the freelist iff its
			 * refcount is zero. Because stack records with a zero
			 * refcount are never considered as valid, it is safe to
			 * union @entries and freelist management state below.
			 * Conversely, as soon as an entry is off the freelist
			 * and its refcount becomes non-zero, the below must not
			 * be accessed until being placed back on the freelist.
			 */
			struct list_head free_list;	/* Links in the freelist */
			unsigned long rcu_state;	/* RCU cookie */
		};
	};
};

struct stack_depot_trie_node {
	const struct stack_depot_trie_node *parent;
	const struct stack_depot_trie_child_array *children;
	u32 leaf_id;
	u16 stack_len;
	struct stack_depot_frame_run run;
	unsigned char data[];
};

struct stack_depot_trie_child_array {
	unsigned int nr_children;
	unsigned int capacity;
	const struct stack_depot_trie_node *children[];
};

struct stack_depot_trie_free_node {
	struct list_head list;
	size_t size;
};

struct stack_depot_trie_free_object {
	struct list_head list;
	unsigned long rcu_state;
	size_t size;
	void *pending_node;
	size_t pending_node_size;
};

static_assert(sizeof(struct stack_depot_trie_node) >=
	      sizeof(struct stack_depot_trie_free_node));

/* Hash table of stored stack records. */
static struct list_head *stack_table;
/* Fixed order of the number of table buckets. Used when KASAN is enabled. */
static unsigned int stack_bucket_number_order;
/* Hash mask for indexing the table. */
static unsigned int stack_hash_mask;

/* Array of memory regions that store stack records. */
static void **stack_pools;
/* Stack pools sorted by address for fast membership checks. */
static void **stack_pools_sorted;
static unsigned int stack_pools_sorted_capacity;
static bool stack_pools_sorted_memblock;
/* Newly allocated pool that is not yet added to stack_pools. */
static void *new_pool;
/* Whether legacy hash storage may contain normal persistent records. */
static bool stack_depot_persistent_hash_record_seen;
/* Number of pools in stack_pools. */
static int pools_num;
static unsigned long pools_min_addr;
static unsigned long pools_max_addr;
/* Offset to the unused space in the currently used pool. */
static size_t pool_offset = DEPOT_POOL_SIZE;
/* Freelist of stack records within stack_pools. */
static LIST_HEAD(free_stacks);

#define STACK_DEPOT_TRIE_FREE_CLASSES \
	((DEPOT_POOL_SIZE >> DEPOT_STACK_ALIGN) + 1)

static struct list_head free_trie_objects[STACK_DEPOT_TRIE_FREE_CLASSES];
static struct list_head pending_trie_objects[STACK_DEPOT_TRIE_FREE_CLASSES];
static struct list_head free_trie_nodes[STACK_DEPOT_TRIE_FREE_CLASSES];
static DECLARE_BITMAP(free_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES);
static DECLARE_BITMAP(pending_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES);
static DECLARE_BITMAP(free_trie_node_map, STACK_DEPOT_TRIE_FREE_CLASSES);
static unsigned int free_trie_pending_nodes;
static bool free_trie_objects_initialized;
/* The lock must be held when performing pool or freelist modifications. */
static DEFINE_RAW_SPINLOCK(pool_lock);

/* Statistics counters for debugfs. */
enum depot_counter_id {
	DEPOT_COUNTER_REFD_ALLOCS,
	DEPOT_COUNTER_REFD_FREES,
	DEPOT_COUNTER_REFD_INUSE,
	DEPOT_COUNTER_FREELIST_SIZE,
	DEPOT_COUNTER_PERSIST_COUNT,
	DEPOT_COUNTER_PERSIST_BYTES,
	DEPOT_COUNTER_COUNT,
};

static long counters[DEPOT_COUNTER_COUNT];
static const char *const counter_names[] = {
	[DEPOT_COUNTER_REFD_ALLOCS]	= "refcounted_allocations",
	[DEPOT_COUNTER_REFD_FREES]	= "refcounted_frees",
	[DEPOT_COUNTER_REFD_INUSE]	= "refcounted_in_use",
	[DEPOT_COUNTER_FREELIST_SIZE]	= "freelist_size",
	[DEPOT_COUNTER_PERSIST_COUNT]	= "persistent_count",
	[DEPOT_COUNTER_PERSIST_BYTES]	= "persistent_bytes",
};

static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);
/* Count helpers rely on saturated refcounts looking negative. */
static_assert(REFCOUNT_SATURATED < 0);

static bool depot_init_pool(void **prealloc);
static void depot_try_keep_new_pool(void **prealloc);

static u32 stack_depot_pool_index_mask(void)
{
	return (1U << DEPOT_POOL_INDEX_BITS) - 1;
}

static u32 stack_depot_offset_mask(void)
{
	return (1U << DEPOT_OFFSET_BITS) - 1;
}

static bool stack_depot_trie_namespace_available(void)
{
	/* Reserve the all-ones pool index as an invalid trie namespace sentinel. */
	return stack_max_pools < stack_depot_pool_index_mask() - 1;
}

u32 __stack_depot_trie_max_leaf_id(void)
{
	if (!stack_depot_trie_namespace_available())
		return 0;

	return (stack_depot_pool_index_mask() - stack_max_pools - 1) <<
		DEPOT_OFFSET_BITS;
}

depot_stack_handle_t __stack_depot_trie_handle(u32 leaf_id)
{
	union handle_parts parts = {};
	u64 pool_index_plus_1;
	u32 pool_delta;
	u32 index;

	if (!leaf_id || !stack_depot_trie_namespace_available())
		return 0;
	if (leaf_id > __stack_depot_trie_max_leaf_id())
		return 0;

	index = leaf_id - 1;
	pool_delta = index >> DEPOT_OFFSET_BITS;
	pool_index_plus_1 = (u64)stack_max_pools + 1 + pool_delta;
	if (pool_index_plus_1 >= stack_depot_pool_index_mask())
		return 0;

	parts.pool_index_plus_1 = pool_index_plus_1;
	parts.offset = index & stack_depot_offset_mask();
	return parts.handle;
}

u32 __stack_depot_trie_leaf_id(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };
	u64 leaf_id;
	u32 pool_delta;

	if (!stack_depot_trie_namespace_available())
		return 0;

	parts.extra = 0;
	if (parts.pool_index_plus_1 <= stack_max_pools)
		return 0;

	pool_delta = parts.pool_index_plus_1 - stack_max_pools - 1;
	if ((u64)pool_delta + stack_max_pools + 1 >= stack_depot_pool_index_mask())
		return 0;

	leaf_id = ((u64)pool_delta << DEPOT_OFFSET_BITS) + parts.offset + 1;
	return leaf_id > U32_MAX ? 0 : leaf_id;
}

struct stack_depot_trie_side_entry {
	const void *leaf;
};

#define STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS 9
#define STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE \
	(1U << STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS)

struct stack_depot_trie_side_dir {
	struct stack_depot_trie_side_entry *chunks[STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE];
};

static struct stack_depot_trie_side_dir **trie_side_table_dirs;
static DEFINE_RAW_SPINLOCK(trie_side_table_lock);
static DEFINE_RAW_SPINLOCK(trie_alloc_lock);
static unsigned int trie_side_table_high_water;
static unsigned int trie_side_table_nr_dirs;
static unsigned int trie_side_table_nr_chunks;
static unsigned int trie_side_table_root_size;
static u32 trie_side_table_max_id;
static u32 trie_side_table_next_id;
static bool trie_side_table_initialized;
static bool trie_side_table_memblock;

/* Lock order: trie_alloc_lock -> pool_lock -> trie_side_table_lock. */

static bool stack_depot_trie_is_ready(void)
{
	/* Pairs with stack_depot_trie_publish_ready(). */
	return smp_load_acquire(&stack_depot_trie_ready);
}

static bool trie_side_table_is_initialized(void)
{
	/* Pairs with trie_side_table_publish_initialized(). */
	return smp_load_acquire(&trie_side_table_initialized);
}

static void stack_depot_trie_publish_ready(void)
{
	/* Pairs with stack_depot_trie_is_ready(). */
	smp_store_release(&stack_depot_trie_ready, true);
}

static void trie_side_table_publish_initialized(void)
{
	/* Pairs with trie_side_table_is_initialized(). */
	smp_store_release(&trie_side_table_initialized, true);
}

static void stack_depot_trie_mark_not_ready(void)
{
	/* Pairs with stack_depot_trie_is_ready(). */
	smp_store_release(&stack_depot_trie_ready, false);
}

static int stack_pool_addr_cmp(const void *a, const void *b)
{
	unsigned long ap = (unsigned long)*(void * const *)a;
	unsigned long bp = (unsigned long)*(void * const *)b;

	return (ap > bp) - (ap < bp);
}

static unsigned int stack_pools_sorted_round_capacity(unsigned int pools)
{
	unsigned int step = PAGE_SIZE / sizeof(*stack_pools_sorted);

	if (!pools)
		pools = 1;
	if (pools > stack_max_pools)
		return 0;
	return min(round_up(pools, step), stack_max_pools);
}

static unsigned int stack_pools_sorted_lower_bound(unsigned long addr,
						   unsigned int pools)
{
	unsigned int left = 0;
	unsigned int right = pools;

	while (left < right) {
		unsigned int mid = left + (right - left) / 2;
		unsigned long mid_start = (unsigned long)stack_pools_sorted[mid];

		if (mid_start < addr)
			left = mid + 1;
		else
			right = mid;
	}

	return left;
}

static int __init stack_depot_trie_init_sorted_pools_memblock(void)
{
	unsigned int capacity;
	size_t bytes;

	if (READ_ONCE(stack_pools_sorted))
		return 0;
	capacity = stack_pools_sorted_round_capacity(READ_ONCE(pools_num) + 1);
	if (!capacity)
		return -ENOMEM;
	bytes = capacity * sizeof(*stack_pools_sorted);
	stack_pools_sorted = memblock_alloc(bytes, PAGE_SIZE);
	if (!stack_pools_sorted)
		return -ENOMEM;
	memset(stack_pools_sorted, 0, bytes);
	WRITE_ONCE(stack_pools_sorted_capacity, capacity);
	WRITE_ONCE(stack_pools_sorted_memblock, true);
	return 0;
}

static int stack_depot_trie_init_sorted_pools(gfp_t gfp_flags)
{
	unsigned long flags;
	unsigned int capacity;
	unsigned int pools;
	void **sorted;

	if (READ_ONCE(stack_pools_sorted))
		return 0;
	capacity = stack_pools_sorted_round_capacity(READ_ONCE(pools_num) + 1);
	if (!capacity)
		return -ENOMEM;
	sorted = kvcalloc(capacity, sizeof(*sorted), gfp_flags);
	if (!sorted)
		return -ENOMEM;

	while (sorted) {
		raw_spin_lock_irqsave(&pool_lock, flags);
		if (stack_pools_sorted) {
			raw_spin_unlock_irqrestore(&pool_lock, flags);
			break;
		}
		pools = READ_ONCE(pools_num);
		if (pools > capacity) {
			raw_spin_unlock_irqrestore(&pool_lock, flags);
			break;
		}
		memcpy(sorted, stack_pools, pools * sizeof(*sorted));
		raw_spin_unlock_irqrestore(&pool_lock, flags);

		sort(sorted, pools, sizeof(*sorted), stack_pool_addr_cmp, NULL);

		raw_spin_lock_irqsave(&pool_lock, flags);
		if (!stack_pools_sorted && pools == READ_ONCE(pools_num)) {
			WRITE_ONCE(stack_pools_sorted_capacity, capacity);
			WRITE_ONCE(stack_pools_sorted_memblock, false);
			WRITE_ONCE(stack_pools_sorted, sorted);
			sorted = NULL;
		}
		raw_spin_unlock_irqrestore(&pool_lock, flags);
	}

	kvfree(sorted);
	return 0;
}

static void stack_pools_sorted_grow(gfp_t gfp_flags)
{
	unsigned int old_capacity;
	unsigned int capacity;
	unsigned long flags;
	unsigned int pools;
	void **old;
	bool old_memblock = false;
	void **sorted;

	old_capacity = READ_ONCE(stack_pools_sorted_capacity);
	if (old_capacity > READ_ONCE(pools_num))
		return;
	capacity = stack_pools_sorted_round_capacity(READ_ONCE(pools_num) + 1);
	if (capacity <= old_capacity)
		return;

	sorted = kvcalloc(capacity, sizeof(*sorted), gfp_flags);
	if (!sorted)
		return;

	for (;;) {
		raw_spin_lock_irqsave(&pool_lock, flags);
		old = stack_pools_sorted;
		if (capacity <= stack_pools_sorted_capacity) {
			raw_spin_unlock_irqrestore(&pool_lock, flags);
			break;
		}
		pools = READ_ONCE(pools_num);
		memcpy(sorted, stack_pools, pools * sizeof(*sorted));
		raw_spin_unlock_irqrestore(&pool_lock, flags);

		sort(sorted, pools, sizeof(*sorted), stack_pool_addr_cmp, NULL);

		raw_spin_lock_irqsave(&pool_lock, flags);
		old = stack_pools_sorted;
		if (capacity > stack_pools_sorted_capacity &&
		    pools == READ_ONCE(pools_num)) {
			old_memblock = stack_pools_sorted_memblock;
			WRITE_ONCE(stack_pools_sorted_capacity, capacity);
			WRITE_ONCE(stack_pools_sorted_memblock, false);
			WRITE_ONCE(stack_pools_sorted, sorted);
			sorted = old;
			raw_spin_unlock_irqrestore(&pool_lock, flags);
			break;
		}
		raw_spin_unlock_irqrestore(&pool_lock, flags);
	}

	if (!old_memblock)
		kvfree(sorted);
}

bool __stack_depot_trie_ready(void)
{
	return __stack_depot_trie_enabled() &&
		stack_depot_trie_is_ready() &&
		READ_ONCE(stack_depot_trie_workspace) &&
		trie_side_table_is_initialized();
}

static unsigned int trie_side_table_top_index(u32 id)
{
	return (id - 1) >> STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS;
}

static unsigned int trie_side_table_root_index(u32 id)
{
	return trie_side_table_top_index(id) >> STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS;
}

static unsigned int trie_side_table_dir_index(u32 id)
{
	return trie_side_table_top_index(id) &
		(STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE - 1);
}

static unsigned int trie_side_table_slot_index(u32 id)
{
	return (id - 1) & (STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE - 1);
}

static struct stack_depot_trie_side_dir *trie_side_table_load_dir(unsigned int root)
{
	/* Pairs with trie_side_table_publish_dir(). */
	return smp_load_acquire(&trie_side_table_dirs[root]);
}

static void trie_side_table_publish_dir(unsigned int root,
					struct stack_depot_trie_side_dir *dir)
{
	/* Pairs with trie_side_table_load_dir(). */
	smp_store_release(&trie_side_table_dirs[root], dir);
}

static struct stack_depot_trie_side_entry *
trie_side_table_dir_load_chunk(struct stack_depot_trie_side_dir *dir,
			       unsigned int idx)
{
	/* Pairs with trie_side_table_dir_publish_chunk(). */
	return smp_load_acquire(&dir->chunks[idx]);
}

static void
trie_side_table_dir_publish_chunk(struct stack_depot_trie_side_dir *dir,
				  unsigned int idx,
				  struct stack_depot_trie_side_entry *chunk)
{
	/* Pairs with trie_side_table_dir_load_chunk(). */
	smp_store_release(&dir->chunks[idx], chunk);
}

static u32
trie_side_table_alloc_id_locked(struct stack_depot_trie_side_prealloc *prealloc)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned int root;
	unsigned int idx;
	u32 id;

	lockdep_assert_held(&trie_side_table_lock);
	if (!trie_side_table_is_initialized())
		return 0;

	id = trie_side_table_next_id + 1;
	if (!id || id > trie_side_table_max_id)
		return 0;

	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		return 0;

	dir = trie_side_table_load_dir(root);
	if (!dir) {
		if (!prealloc || !prealloc->dir)
			return 0;
		dir = prealloc->dir;
		prealloc->dir = NULL;
		trie_side_table_publish_dir(root, dir);
		trie_side_table_nr_dirs++;
		if (trie_side_table_high_water < root + 1)
			trie_side_table_high_water = root + 1;
	}

	idx = trie_side_table_dir_index(id);
	chunk = trie_side_table_dir_load_chunk(dir, idx);
	if (!chunk) {
		if (!prealloc || !prealloc->chunk)
			return 0;
		chunk = prealloc->chunk;
		prealloc->chunk = NULL;
		trie_side_table_dir_publish_chunk(dir, idx, chunk);
		trie_side_table_nr_chunks++;
	}

	WRITE_ONCE(trie_side_table_next_id, id);
	return id;
}

static size_t trie_side_table_root_bytes(unsigned int root_size)
{
	size_t bytes;

	if (check_mul_overflow((size_t)root_size,
			       sizeof(*trie_side_table_dirs), &bytes))
		return 0;
	return PAGE_ALIGN(bytes);
}

static size_t trie_side_table_dir_bytes(void)
{
	return PAGE_ALIGN(sizeof(struct stack_depot_trie_side_dir));
}

static unsigned int trie_side_table_dir_order(void)
{
	return get_order(trie_side_table_dir_bytes());
}

static size_t trie_side_table_chunk_bytes(void)
{
	return PAGE_ALIGN(STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE *
			  sizeof(struct stack_depot_trie_side_entry));
}

static unsigned int trie_side_table_chunk_order(void)
{
	return get_order(trie_side_table_chunk_bytes());
}

static void trie_side_table_free_chunk(struct stack_depot_trie_side_entry *chunk)
{
	if (chunk)
		free_pages((unsigned long)chunk, trie_side_table_chunk_order());
}

static void trie_side_table_free_dir(struct stack_depot_trie_side_dir *dir)
{
	if (dir)
		free_pages((unsigned long)dir, trie_side_table_dir_order());
}

static int
trie_side_table_install(struct stack_depot_trie_side_dir **dirs,
			unsigned int root_size, u32 max_id,
			struct stack_depot_trie_side_dir *first_dir,
			struct stack_depot_trie_side_entry *first_chunk,
			bool memblock)
{
	if (trie_side_table_is_initialized())
		return 0;
	if (!dirs || !root_size || !max_id)
		return -EINVAL;

	WRITE_ONCE(trie_side_table_dirs, dirs);
	WRITE_ONCE(trie_side_table_root_size, root_size);
	WRITE_ONCE(trie_side_table_high_water, 0);
	WRITE_ONCE(trie_side_table_nr_dirs, 0);
	WRITE_ONCE(trie_side_table_nr_chunks, 0);
	WRITE_ONCE(trie_side_table_max_id, max_id);
	WRITE_ONCE(trie_side_table_next_id, 0);
	WRITE_ONCE(trie_side_table_memblock, memblock);
	if (first_dir) {
		trie_side_table_publish_dir(0, first_dir);
		WRITE_ONCE(trie_side_table_high_water, 1);
		WRITE_ONCE(trie_side_table_nr_dirs, 1);
	}
	if (first_dir && first_chunk) {
		trie_side_table_dir_publish_chunk(first_dir, 0, first_chunk);
		WRITE_ONCE(trie_side_table_nr_chunks, 1);
	}
	trie_side_table_publish_initialized();
	return 0;
}

static unsigned int trie_side_table_root_size_for_max_id(u32 max_leaf_id)
{
	unsigned int top_size;

	top_size = DIV_ROUND_UP(max_leaf_id, STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE);
	return DIV_ROUND_UP(top_size, STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE);
}

static int __init __stack_depot_trie_side_table_init_memblock(void)
{
	struct stack_depot_trie_side_dir **dirs;
	struct stack_depot_trie_side_dir *first_dir;
	struct stack_depot_trie_side_entry *first_chunk;
	size_t dir_bytes;
	size_t chunk_bytes;
	size_t root_bytes;
	u32 max_leaf_id;
	unsigned int root_size;

	if (trie_side_table_is_initialized())
		return 0;

	max_leaf_id = __stack_depot_trie_max_leaf_id();
	if (!max_leaf_id)
		return -EINVAL;
	root_size = trie_side_table_root_size_for_max_id(max_leaf_id);
	root_bytes = trie_side_table_root_bytes(root_size);
	dir_bytes = trie_side_table_dir_bytes();
	chunk_bytes = trie_side_table_chunk_bytes();
	if (!root_bytes || !dir_bytes || !chunk_bytes)
		return -ENOMEM;

	dirs = memblock_alloc(root_bytes, PAGE_SIZE);
	if (!dirs)
		return -ENOMEM;
	memset(dirs, 0, root_bytes);
	first_dir = memblock_alloc(dir_bytes, PAGE_SIZE);
	if (!first_dir) {
		memblock_free(dirs, root_bytes);
		return -ENOMEM;
	}
	memset(first_dir, 0, dir_bytes);
	first_chunk = memblock_alloc(chunk_bytes, PAGE_SIZE);
	if (!first_chunk) {
		memblock_free(first_dir, dir_bytes);
		memblock_free(dirs, root_bytes);
		return -ENOMEM;
	}
	memset(first_chunk, 0, chunk_bytes);

	return trie_side_table_install(dirs, root_size, max_leaf_id, first_dir,
				       first_chunk, true);
}

static size_t stack_depot_trie_workspace_size(void)
{
	return sizeof(*stack_depot_trie_workspace);
}

static int
stack_depot_trie_install_workspace(struct stack_depot_trie_alloc_workspace *workspace)
{
	if (READ_ONCE(stack_depot_trie_workspace))
		return 0;
	if (!workspace)
		return -EINVAL;

	WRITE_ONCE(stack_depot_trie_workspace, workspace);
	return 0;
}

static int __init stack_depot_trie_init_workspace_memblock(void)
{
	struct stack_depot_trie_alloc_workspace *workspace;
	size_t size;

	if (READ_ONCE(stack_depot_trie_workspace))
		return 0;

	size = stack_depot_trie_workspace_size();
	workspace = memblock_alloc(size, __alignof__(*workspace));
	if (!workspace)
		return -ENOMEM;
	memset(workspace, 0, size);

	return stack_depot_trie_install_workspace(workspace);
}

static int stack_depot_trie_init_workspace(gfp_t gfp_flags)
{
	struct stack_depot_trie_alloc_workspace *workspace;

	if (READ_ONCE(stack_depot_trie_workspace))
		return 0;

	workspace = kvzalloc(stack_depot_trie_workspace_size(), gfp_flags);
	if (!workspace)
		return -ENOMEM;

	return stack_depot_trie_install_workspace(workspace);
}

static int __init stack_depot_trie_init_memblock(void)
{
	int ret;

	if (!__stack_depot_trie_enabled())
		return 0;

	ret = stack_depot_trie_init_workspace_memblock();
	if (ret)
		return ret;
	/* Memblock allocations are permanent; keep successful pieces reusable. */
	ret = stack_depot_trie_init_sorted_pools_memblock();
	if (ret)
		return ret;
	ret = __stack_depot_trie_side_table_init_memblock();
	if (ret)
		return ret;

	stack_depot_trie_publish_ready();
	return 0;
}

static int stack_depot_trie_init(gfp_t gfp_flags)
{
	int ret;

	if (!__stack_depot_trie_enabled())
		return 0;

	ret = stack_depot_trie_init_workspace(gfp_flags);
	if (ret)
		return ret;
	ret = stack_depot_trie_init_sorted_pools(gfp_flags);
	if (ret)
		return ret;
	ret = __stack_depot_trie_side_table_init(gfp_flags);
	if (ret)
		return ret;

	stack_depot_trie_publish_ready();
	return 0;
}

static const void *
trie_side_table_load_leaf(struct stack_depot_trie_side_entry *chunk,
			  unsigned int slot)
{
	/* Pairs with trie_side_table_store_leaf(). */
	return smp_load_acquire(&chunk[slot].leaf);
}

static void
trie_side_table_store_leaf(struct stack_depot_trie_side_entry *chunk,
			   unsigned int slot, const void *leaf)
{
	/* Pairs with trie_side_table_load_leaf(). */
	smp_store_release(&chunk[slot].leaf, leaf);
}

static void
trie_side_table_clear_entry(struct stack_depot_trie_side_entry *chunk,
			    unsigned int slot)
{
	trie_side_table_store_leaf(chunk, slot, NULL);
}

int __stack_depot_trie_side_table_init(gfp_t gfp_flags)
{
	struct stack_depot_trie_side_dir **dirs;
	unsigned int root_size;
	size_t root_bytes;
	u32 max_leaf_id;

	if (trie_side_table_is_initialized())
		return 0;

	max_leaf_id = __stack_depot_trie_max_leaf_id();
	if (!max_leaf_id)
		return -EINVAL;

	root_size = trie_side_table_root_size_for_max_id(max_leaf_id);
	root_bytes = trie_side_table_root_bytes(root_size);
	if (!root_bytes)
		return -ENOMEM;
	dirs = kvcalloc(root_size, sizeof(*dirs), gfp_flags);
	if (!dirs)
		return -ENOMEM;

	return trie_side_table_install(dirs, root_size, max_leaf_id, NULL, NULL,
				       false);
}

void __stack_depot_trie_side_table_destroy(void)
{
	struct stack_depot_trie_side_dir *dir;
	unsigned int high_water;
	unsigned int j;
	unsigned int i;

	if (!trie_side_table_is_initialized())
		return;
	stack_depot_trie_mark_not_ready();
	/* Pairs with trie_side_table_is_initialized(). */
	smp_store_release(&trie_side_table_initialized, false);
	synchronize_rcu();

	high_water = READ_ONCE(trie_side_table_high_water);
	if (!READ_ONCE(trie_side_table_memblock)) {
		for (i = 0; i < high_water; i++) {
			dir = trie_side_table_dirs[i];
			if (!dir)
				continue;
			for (j = 0; j < STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE; j++)
				trie_side_table_free_chunk(dir->chunks[j]);
			trie_side_table_free_dir(dir);
		}
		kvfree(trie_side_table_dirs);
	}
	trie_side_table_dirs = NULL;
	WRITE_ONCE(trie_side_table_high_water, 0);
	WRITE_ONCE(trie_side_table_nr_dirs, 0);
	WRITE_ONCE(trie_side_table_nr_chunks, 0);
	WRITE_ONCE(trie_side_table_root_size, 0);
	WRITE_ONCE(trie_side_table_max_id, 0);
	WRITE_ONCE(trie_side_table_next_id, 0);
	WRITE_ONCE(trie_side_table_memblock, false);
}

bool __stack_depot_trie_side_table_prealloc_needed(void)
{
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	bool needed;
	u32 id;
	unsigned int root;

	if (!trie_side_table_is_initialized())
		return false;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	id = READ_ONCE(trie_side_table_next_id) + 1;
	if (!id || id > READ_ONCE(trie_side_table_max_id)) {
		needed = false;
		goto out;
	}

	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size) {
		needed = false;
		goto out;
	}

	dir = trie_side_table_load_dir(root);
	needed = !dir || !trie_side_table_dir_load_chunk(dir,
							 trie_side_table_dir_index(id));
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return needed;
}

static void *trie_side_table_alloc_page(gfp_t gfp_flags, unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_nested_mask(gfp_flags) | __GFP_ZERO,
			   order);
	return page ? page_address(page) : NULL;
}

int
__stack_depot_trie_side_table_prealloc(gfp_t gfp_flags,
				       struct stack_depot_trie_side_prealloc *prealloc)
{
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	bool need_chunk;
	bool need_dir;
	u32 id;
	unsigned int root;

	if (!prealloc || prealloc->dir || prealloc->chunk)
		return -EINVAL;
	if (!trie_side_table_is_initialized())
		return 0;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	id = READ_ONCE(trie_side_table_next_id) + 1;
	if (!id || id > READ_ONCE(trie_side_table_max_id)) {
		raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
		return 0;
	}
	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size) {
		raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
		return 0;
	}
	dir = trie_side_table_load_dir(root);
	need_dir = !dir;
	need_chunk = need_dir || !trie_side_table_dir_load_chunk(dir,
								 trie_side_table_dir_index(id));
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);

	if (need_dir) {
		unsigned int order = trie_side_table_dir_order();

		prealloc->dir = trie_side_table_alloc_page(gfp_flags, order);
		if (!prealloc->dir)
			return -ENOMEM;
	}
	if (need_chunk) {
		unsigned int order = trie_side_table_chunk_order();

		prealloc->chunk = trie_side_table_alloc_page(gfp_flags, order);
		if (!prealloc->chunk) {
			trie_side_table_free_dir(prealloc->dir);
			prealloc->dir = NULL;
			return -ENOMEM;
		}
	}

	return 0;
}

void
__stack_depot_trie_side_table_free_prealloc(struct stack_depot_trie_side_prealloc *prealloc)
{
	if (!prealloc)
		return;
	trie_side_table_free_dir(prealloc->dir);
	trie_side_table_free_chunk(prealloc->chunk);
	prealloc->dir = NULL;
	prealloc->chunk = NULL;
}

u32
__stack_depot_trie_side_table_alloc_id(struct stack_depot_trie_side_prealloc *prealloc)
{
	unsigned long flags;
	u32 id;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	id = trie_side_table_alloc_id_locked(prealloc);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return id;
}

static u32 trie_side_table_alloc_id_trylock(void)
{
	unsigned long flags;
	u32 id;

	if (!raw_spin_trylock_irqsave(&trie_side_table_lock, flags))
		return 0;
	id = trie_side_table_alloc_id_locked(NULL);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return id;
}

void __stack_depot_trie_side_table_revoke_latest(u32 id)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	unsigned int slot;
	unsigned int root;

	if (!trie_side_table_is_initialized() || !id ||
	    id != READ_ONCE(trie_side_table_next_id))
		return;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id != trie_side_table_next_id)
		goto out;
	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		goto out;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		goto out;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		goto out;

	slot = trie_side_table_slot_index(id);
	trie_side_table_clear_entry(chunk, slot);
	WRITE_ONCE(trie_side_table_next_id, id - 1);
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
}

static bool trie_side_table_revoke_latest_trylock(u32 id)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	unsigned int slot;
	unsigned int root;
	bool ret = false;

	if (!trie_side_table_is_initialized() || !id ||
	    id != READ_ONCE(trie_side_table_next_id))
		return false;

	if (!raw_spin_trylock_irqsave(&trie_side_table_lock, flags))
		return false;
	if (id != trie_side_table_next_id)
		goto out;
	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		goto out;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		goto out;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		goto out;

	slot = trie_side_table_slot_index(id);
	trie_side_table_clear_entry(chunk, slot);
	WRITE_ONCE(trie_side_table_next_id, id - 1);
	ret = true;
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return ret;
}

void __stack_depot_trie_side_table_restore(u32 id, const void *entry)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	unsigned int root;

	if (!trie_side_table_is_initialized() || !id)
		return;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id > trie_side_table_next_id)
		goto out;
	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		goto out;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		goto out;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		goto out;

	if (entry)
		trie_side_table_store_leaf(chunk, trie_side_table_slot_index(id), entry);
	else
		trie_side_table_clear_entry(chunk, trie_side_table_slot_index(id));
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
}

int __stack_depot_trie_side_table_store(u32 id, const void *entry)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned long flags;
	unsigned int root;
	int ret = -EINVAL;

	if (!trie_side_table_is_initialized() || !id || !entry)
		return -EINVAL;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id > trie_side_table_next_id)
		goto out;
	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		goto out;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		goto out;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		goto out;

	trie_side_table_store_leaf(chunk, trie_side_table_slot_index(id), entry);
	ret = 0;
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return ret;
}

static struct stack_depot_trie_side_entry *
trie_side_table_chunk_locked(u32 id, unsigned int *slot)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned int root;

	lockdep_assert_held(&trie_side_table_lock);

	if (!trie_side_table_is_initialized() || !id || id > trie_side_table_next_id)
		return NULL;

	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		return NULL;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		return NULL;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		return NULL;

	*slot = trie_side_table_slot_index(id);
	return chunk;
}

const void *__stack_depot_trie_side_table_lookup(u32 id)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned int root;

	if (!trie_side_table_is_initialized() || !id)
		return NULL;

	root = trie_side_table_root_index(id);
	if (root >= trie_side_table_root_size)
		return NULL;

	dir = trie_side_table_load_dir(root);
	if (!dir)
		return NULL;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		return NULL;

	return trie_side_table_load_leaf(chunk, trie_side_table_slot_index(id));
}

size_t __stack_depot_trie_side_table_entries(void)
{
	return trie_side_table_is_initialized() ?
		READ_ONCE(trie_side_table_next_id) : 0;
}

size_t __stack_depot_trie_side_table_bytes(void)
{
	unsigned int nr_dirs;
	unsigned int nr_chunks;
	size_t dir_bytes;
	size_t bytes;
	size_t root_bytes;

	if (!trie_side_table_is_initialized())
		return 0;
	root_bytes = trie_side_table_root_bytes(trie_side_table_root_size);
	if (!root_bytes)
		return SIZE_MAX;

	nr_dirs = READ_ONCE(trie_side_table_nr_dirs);
	nr_chunks = READ_ONCE(trie_side_table_nr_chunks);
	if (check_mul_overflow((size_t)nr_dirs, trie_side_table_dir_bytes(),
			       &dir_bytes))
		return SIZE_MAX;
	if (check_mul_overflow((size_t)nr_chunks, trie_side_table_chunk_bytes(),
			       &bytes))
		return SIZE_MAX;
	if (check_add_overflow(root_bytes, dir_bytes, &dir_bytes))
		return SIZE_MAX;
	if (check_add_overflow(dir_bytes, bytes, &bytes))
		return SIZE_MAX;

	return bytes;
}

size_t __stack_depot_trie_pool_alloc_size(size_t size)
{
	size_t align = 1UL << DEPOT_STACK_ALIGN;
	size_t aligned;

	if (!size || size > DEPOT_POOL_SIZE)
		return 0;
	if (check_add_overflow(size, align - 1, &aligned))
		return 0;
	aligned = ALIGN(size, align);
	return aligned <= DEPOT_POOL_SIZE ? aligned : 0;
}

static size_t trie_object_header_size(void)
{
	return ALIGN(sizeof(struct stack_depot_trie_free_object),
		     1UL << DEPOT_STACK_ALIGN);
}

static size_t trie_object_alloc_size(size_t size)
{
	size_t alloc_size;

	size = __stack_depot_trie_pool_alloc_size(size);
	if (!size)
		return 0;
	if (check_add_overflow(trie_object_header_size(), size,
			       &alloc_size))
		return 0;
	return alloc_size <= DEPOT_POOL_SIZE ? alloc_size : 0;
}

static struct stack_depot_trie_free_object *trie_object_header(const void *ptr)
{
	return (void *)ptr - trie_object_header_size();
}

static void *trie_object_payload(struct stack_depot_trie_free_object *free)
{
	return (void *)free + trie_object_header_size();
}

static void trie_free_object_buckets_init_locked(void)
{
	unsigned int i;

	lockdep_assert_held(&pool_lock);

	if (free_trie_objects_initialized)
		return;
	for (i = 0; i < ARRAY_SIZE(free_trie_objects); i++) {
		INIT_LIST_HEAD(&free_trie_objects[i]);
		INIT_LIST_HEAD(&pending_trie_objects[i]);
		INIT_LIST_HEAD(&free_trie_nodes[i]);
	}
	free_trie_objects_initialized = true;
}

static unsigned int trie_free_class(size_t size)
{
	size = __stack_depot_trie_pool_alloc_size(size);
	if (!size)
		return 0;

	return size >> DEPOT_STACK_ALIGN;
}

static void trie_free_list_add(struct list_head *entry, struct list_head *heads,
			       unsigned long *map, unsigned int class, bool tail)
{
	lockdep_assert_held(&pool_lock);

	if (WARN_ON_ONCE(!class || class >= STACK_DEPOT_TRIE_FREE_CLASSES))
		return;
	if (tail)
		list_add_tail(entry, &heads[class]);
	else
		list_add(entry, &heads[class]);
	__set_bit(class, map);
}

static void trie_free_list_del(struct list_head *entry, struct list_head *heads,
			       unsigned long *map, unsigned int class)
{
	lockdep_assert_held(&pool_lock);

	if (WARN_ON_ONCE(!class || class >= STACK_DEPOT_TRIE_FREE_CLASSES))
		return;
	list_del_init(entry);
	if (list_empty(&heads[class]))
		__clear_bit(class, map);
}

static void *trie_object_init_fresh(void *ptr, size_t size)
{
	struct stack_depot_trie_free_object *free = ptr;

	free->size = __stack_depot_trie_pool_alloc_size(size);
	free->rcu_state = 0;
	free->pending_node = NULL;
	free->pending_node_size = 0;
	INIT_LIST_HEAD(&free->list);
	return trie_object_payload(free);
}

static void depot_record_pool_locked(void *pool)
{
	unsigned long start = (unsigned long)pool;
	unsigned long end;
	unsigned int pools = READ_ONCE(pools_num);
	unsigned int pos;

	lockdep_assert_held(&pool_lock);
	if (!pool || check_add_overflow(start, DEPOT_POOL_SIZE, &end))
		return;

	if (!pools_min_addr || start < pools_min_addr)
		pools_min_addr = start;
	if (end > pools_max_addr)
		pools_max_addr = end;

	if (!stack_pools_sorted || READ_ONCE(stack_pools_sorted_capacity) <= pools)
		return;
	pos = stack_pools_sorted_lower_bound(start, pools);
	memmove(&stack_pools_sorted[pos + 1], &stack_pools_sorted[pos],
		(pools - pos) * sizeof(*stack_pools_sorted));
	stack_pools_sorted[pos] = pool;
}

static void depot_forget_pool_locked(void *pool)
{
	unsigned int pools = READ_ONCE(pools_num);
	unsigned int i;

	lockdep_assert_held(&pool_lock);
	if (!pool || !stack_pools_sorted || READ_ONCE(stack_pools_sorted_capacity) < pools)
		return;

	i = stack_pools_sorted_lower_bound((unsigned long)pool, pools);
	if (i >= pools || stack_pools_sorted[i] != pool)
		return;
	memmove(&stack_pools_sorted[i], &stack_pools_sorted[i + 1],
		(pools - i - 1) * sizeof(*stack_pools_sorted));
	stack_pools_sorted[pools - 1] = NULL;
}

static bool trie_pool_range_contains_locked(const void *ptr, size_t size)
{
	unsigned long start = (unsigned long)ptr;
	unsigned long end;
	unsigned int pools = READ_ONCE(pools_num);
	unsigned int left = 0;
	unsigned int right = pools;
	unsigned int pos;
	unsigned long pool_start;

	lockdep_assert_held(&pool_lock);

	if (!ptr || !size || check_add_overflow(start, size, &end))
		return false;
	if (!stack_pools_sorted || READ_ONCE(stack_pools_sorted_capacity) < pools) {
		unsigned int i;

		if (!stack_pools)
			return false;
		for (i = 0; i < pools; i++) {
			if (!stack_pools[i])
				continue;
			pool_start = (unsigned long)stack_pools[i];
			if (start >= pool_start && end <= pool_start + DEPOT_POOL_SIZE)
				return true;
		}
		return false;
	}
	if (pools_min_addr && (start < pools_min_addr || end > pools_max_addr))
		return false;

	left = stack_pools_sorted_lower_bound(start + 1, right);
	if (!left)
		return false;

	pos = left - 1;
	pool_start = (unsigned long)stack_pools_sorted[pos];
	return end <= pool_start + DEPOT_POOL_SIZE;
}

static bool trie_pool_contains_locked(const void *ptr)
{
	return trie_pool_range_contains_locked(ptr, 1);
}

static bool trie_pool_mark_contains(const struct stack_depot_trie_pool_mark *mark,
				    const void *ptr)
{
	const void *start;
	const void *end;

	if (!mark || !mark->pool)
		return false;
	start = mark->pool + mark->offset;
	end = start + mark->size;
	return ptr >= start && ptr < end;
}

static void trie_free_object_locked(const void *ptr, unsigned long rcu_state)
{
	struct stack_depot_trie_free_object *free;
	unsigned int class;

	lockdep_assert_held(&pool_lock);

	if (!ptr)
		return;
	trie_free_object_buckets_init_locked();
	free = trie_object_header(ptr);
	if (!trie_pool_contains_locked(free))
		return;
	free->rcu_state = rcu_state;
	class = trie_free_class(free->size);
	INIT_LIST_HEAD(&free->list);
	if (poll_state_synchronize_rcu(rcu_state))
		trie_free_list_add(&free->list, free_trie_objects,
				   free_trie_object_map, class, false);
	else
		trie_free_list_add(&free->list, pending_trie_objects,
				   pending_trie_object_map, class, true);
}

static void trie_add_free_node_locked(void *ptr, size_t size)
{
	struct stack_depot_trie_free_node *free = ptr;
	unsigned int class;

	lockdep_assert_held(&pool_lock);

	size = __stack_depot_trie_pool_alloc_size(size);
	if (!ptr || size < sizeof(*free))
		return;

	free->size = size;
	INIT_LIST_HEAD(&free->list);
	class = trie_free_class(size);
	trie_free_list_add(&free->list, free_trie_nodes, free_trie_node_map,
			   class, false);
}

static void trie_drain_free_object_node_locked(struct stack_depot_trie_free_object *free)
{
	lockdep_assert_held(&pool_lock);

	if (!free->pending_node)
		return;
	trie_add_free_node_locked(free->pending_node, free->pending_node_size);
	free->pending_node = NULL;
	free->pending_node_size = 0;
	free_trie_pending_nodes--;
}

static void trie_drain_pending_objects_locked(void)
{
	struct stack_depot_trie_free_object *free;
	struct stack_depot_trie_free_object *tmp;
	unsigned int class;

	lockdep_assert_held(&pool_lock);

	if (!free_trie_pending_nodes &&
	    bitmap_empty(pending_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES))
		return;
	for_each_set_bit(class, pending_trie_object_map,
			 STACK_DEPOT_TRIE_FREE_CLASSES) {
		list_for_each_entry_safe(free, tmp, &pending_trie_objects[class], list) {
			if (!poll_state_synchronize_rcu(free->rcu_state))
				break;
			trie_drain_free_object_node_locked(free);
			trie_free_list_del(&free->list, pending_trie_objects,
					   pending_trie_object_map, class);
			free->rcu_state = 0;
			trie_free_list_add(&free->list, free_trie_objects,
					   free_trie_object_map, class, false);
		}
	}
}

static void trie_free_object_tail_locked(void *ptr, size_t size);

static void *trie_pop_free_node(size_t size)
{
	struct stack_depot_trie_free_node *free;
	unsigned int class;
	size_t old_size;

	lockdep_assert_held(&pool_lock);

	size = __stack_depot_trie_pool_alloc_size(size);
	if (!size)
		return NULL;
	class = trie_free_class(size);
	class = find_next_bit(free_trie_node_map, STACK_DEPOT_TRIE_FREE_CLASSES,
			      class);
	if (class >= STACK_DEPOT_TRIE_FREE_CLASSES)
		return NULL;
	free = list_first_entry(&free_trie_nodes[class], typeof(*free), list);
	if (WARN_ON_ONCE(free->size < size))
		return NULL;
	old_size = free->size;
	trie_free_list_del(&free->list, free_trie_nodes, free_trie_node_map,
			   class);
	if (old_size > size)
		trie_free_object_tail_locked((void *)free + size, old_size - size);
	return free;
}

static void trie_free_object_tail_locked(void *ptr, size_t size)
{
	struct stack_depot_trie_free_object *free = ptr;
	size_t header_size = trie_object_header_size();
	size_t tail_size;

	lockdep_assert_held(&pool_lock);

	if (size >= header_size + (1UL << DEPOT_STACK_ALIGN)) {
		tail_size = size - header_size;
		free->size = tail_size;
		free->rcu_state = get_completed_synchronize_rcu();
		free->pending_node = NULL;
		free->pending_node_size = 0;
		INIT_LIST_HEAD(&free->list);
		trie_free_list_add(&free->list, free_trie_objects,
				   free_trie_object_map, trie_free_class(tail_size),
				   false);
		return;
	}

	trie_add_free_node_locked(ptr, size);
}

static void trie_split_free_object_locked(struct stack_depot_trie_free_object *free,
					  size_t size)
{
	void *tail;
	size_t old_size = free->size;
	size_t tail_size;

	lockdep_assert_held(&pool_lock);

	if (old_size <= size)
		return;
	free->size = size;
	tail = trie_object_payload(free) + size;
	tail_size = old_size - size;
	trie_free_object_tail_locked(tail, tail_size);
}

static void trie_retire_object_node_locked(const void *ptr, const void *node,
					   size_t node_size)
{
	struct stack_depot_trie_free_object *free;
	size_t size;

	lockdep_assert_held(&pool_lock);
	if (!ptr)
		return;

	trie_free_object_buckets_init_locked();
	free = trie_object_header(ptr);
	if (trie_pool_contains_locked(free)) {
		free->pending_node = NULL;
		free->pending_node_size = 0;
		size = __stack_depot_trie_pool_alloc_size(node_size);
		if (node && size >= sizeof(struct stack_depot_trie_free_node) &&
		    trie_pool_range_contains_locked(node, size)) {
			free->pending_node = (void *)node;
			free->pending_node_size = size;
			free_trie_pending_nodes++;
		}
		free->rcu_state = get_state_synchronize_rcu();
		trie_free_list_add(&free->list, pending_trie_objects,
				   pending_trie_object_map,
				   trie_free_class(free->size), true);
	}
}

static void trie_retire_object_node(const void *ptr, const void *node,
				    size_t node_size)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pool_lock, flags);
	trie_retire_object_node_locked(ptr, node, node_size);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

static void trie_retire_object(const void *ptr)
{
	trie_retire_object_node(ptr, NULL, 0);
}

static void *trie_pop_free_object(size_t size)
{
	struct stack_depot_trie_free_object *free;
	unsigned int class;

	lockdep_assert_held(&pool_lock);

	size = __stack_depot_trie_pool_alloc_size(size);
	if (!size)
		return NULL;
	class = trie_free_class(size);
	class = find_next_bit(free_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES,
			      class);
	if (class >= STACK_DEPOT_TRIE_FREE_CLASSES)
		return NULL;

	free = list_first_entry(&free_trie_objects[class], typeof(*free), list);
	if (WARN_ON_ONCE(free->size < size))
		return NULL;
	trie_drain_free_object_node_locked(free);
	trie_free_list_del(&free->list, free_trie_objects,
			   free_trie_object_map, class);
	free->rcu_state = 0;
	trie_split_free_object_locked(free, size);
	return trie_object_payload(free);
}

void *__stack_depot_trie_pool_prealloc(gfp_t gfp_flags)
{
	struct page *page;

	if (!gfpflags_allow_spinning(gfp_flags))
		return NULL;

	page = alloc_pages(gfp_nested_mask(gfp_flags), DEPOT_POOL_ORDER);
	return page ? page_address(page) : NULL;
}

void __stack_depot_trie_pool_free_prealloc(void *prealloc)
{
	if (prealloc)
		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
}

int __stack_depot_trie_alloc_prealloc(gfp_t alloc_flags,
				      depot_flags_t depot_flags,
				      void **pool_prealloc,
				      struct stack_depot_trie_side_prealloc *side_prealloc)
{
	bool needs_side_prealloc;
	bool can_alloc;
	int ret = 0;

	if (!pool_prealloc || !side_prealloc || *pool_prealloc ||
	    side_prealloc->dir || side_prealloc->chunk)
		return -EINVAL;

	can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) &&
		gfpflags_allow_spinning(alloc_flags);
	if (can_alloc)
		stack_pools_sorted_grow(alloc_flags);
	needs_side_prealloc = __stack_depot_trie_side_table_prealloc_needed();
	if (can_alloc && !READ_ONCE(new_pool))
		*pool_prealloc = __stack_depot_trie_pool_prealloc(alloc_flags);
	if (needs_side_prealloc && !can_alloc)
		return -ENOSPC;
	if (can_alloc && needs_side_prealloc)
		ret = __stack_depot_trie_side_table_prealloc(alloc_flags, side_prealloc);

	if (needs_side_prealloc && ret)
		return -ENOSPC;
	return 0;
}

void *
__stack_depot_trie_pool_carve_current(size_t size,
				      struct stack_depot_trie_pool_mark *mark)
{
	unsigned long flags;
	size_t alloc_size;
	void *pool;
	void *ptr = NULL;

	if (!mark)
		return NULL;
	memset(mark, 0, sizeof(*mark));

	alloc_size = __stack_depot_trie_pool_alloc_size(size);
	if (!alloc_size)
		return NULL;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return NULL;
	printk_deferred_enter();
	if (!stack_pools || pools_num < 1)
		goto out;
	if (WARN_ON_ONCE(pool_offset > DEPOT_POOL_SIZE))
		goto out;
	if (alloc_size > DEPOT_POOL_SIZE - pool_offset)
		goto out;

	mark->pool_index = pools_num - 1;
	pool = stack_pools[mark->pool_index];
	if (WARN_ON_ONCE(!pool))
		goto out;

	mark->offset = pool_offset;
	mark->size = alloc_size;
	ptr = pool + pool_offset;
	pool_offset += alloc_size;
out:
	printk_deferred_exit();
	raw_spin_unlock_irqrestore(&pool_lock, flags);
	return ptr;
}

bool __stack_depot_trie_pool_try_rollback(const struct stack_depot_trie_pool_mark *mark)
{
	unsigned long flags;
	size_t end;
	bool ret = false;

	if (!mark || !mark->size)
		return false;
	if (check_add_overflow(mark->offset, mark->size, &end))
		return false;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return false;
	if (mark->pool_index != pools_num - 1 || pool_offset != end)
		goto out;
	if (mark->added_pool) {
		if (mark->offset || stack_pools[mark->pool_index] != mark->pool)
			goto out;
		if (new_pool && new_pool != STACK_DEPOT_POISON)
			goto out;
		depot_forget_pool_locked(mark->pool);
		stack_pools[mark->pool_index] = NULL;
		WRITE_ONCE(pools_num, mark->pool_index);
		pool_offset = mark->prev_offset;
		WRITE_ONCE(new_pool, mark->pool);
		ret = true;
	} else {
		pool_offset = mark->offset;
		ret = true;
	}
out:
	raw_spin_unlock_irqrestore(&pool_lock, flags);

	return ret;
}

static int trie_pool_add_object_size(size_t size, size_t *total)
{
	size_t alloc_size;

	alloc_size = trie_object_alloc_size(size);
	if (!alloc_size)
		return -EINVAL;
	if (check_add_overflow(*total, alloc_size, total))
		return -EINVAL;
	return *total <= DEPOT_POOL_SIZE ? 0 : -EINVAL;
}

static int trie_pool_add_size(size_t size, size_t *total)
{
	size_t alloc_size;

	alloc_size = __stack_depot_trie_pool_alloc_size(size);
	if (!alloc_size)
		return -EINVAL;
	if (check_add_overflow(*total, alloc_size, total))
		return -EINVAL;
	return *total <= DEPOT_POOL_SIZE ? 0 : -EINVAL;
}

static void trie_pool_release_reused_objects_locked(struct stack_depot_trie_pool_request *req)
{
	unsigned long completed;
	unsigned int i;

	lockdep_assert_held(&pool_lock);

	if (!req)
		return;
	completed = get_completed_synchronize_rcu();
	for (i = 0; req->node_slots && i < req->nr_node_slots; i++) {
		void *node = req->node_slots[i].node;

		if (node && !trie_pool_mark_contains(req->mark, node)) {
			trie_add_free_node_locked(node, req->node_slots[i].size);
			req->node_slots[i].node = NULL;
		}
	}
	for (i = 0; req->child_slots && i < req->nr_child_slots; i++) {
		void *array = req->child_slots[i].array;

		if (array &&
		    !trie_pool_mark_contains(req->mark,
					     trie_object_header(array))) {
			trie_free_object_locked(array, completed);
			req->child_slots[i].array = NULL;
		}
	}
	if (req->storage && *req->storage &&
	    !trie_pool_mark_contains(req->mark,
				      trie_object_header(*req->storage))) {
		trie_free_object_locked(*req->storage, completed);
		*req->storage = NULL;
	}
}

static void trie_pool_release_reused_objects(struct stack_depot_trie_pool_request *req)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pool_lock, flags);
	trie_pool_release_reused_objects_locked(req);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

static void trie_pool_release_reused_objects_trylock(struct stack_depot_trie_pool_request *req)
{
	unsigned long flags;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return;
	trie_pool_release_reused_objects_locked(req);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

int __stack_depot_trie_pool_carve(struct stack_depot_trie_pool_request *req)
{
	unsigned long flags;
	unsigned int i;
	size_t offset;
	size_t total = 0;
	void *pool;
	int ret = -EINVAL;

	if (!req || !req->mark)
		return -EINVAL;
	memset(req->mark, 0, sizeof(*req->mark));
	if (!req->storage || *req->storage ||
	    (!req->node_slots && req->nr_node_slots) ||
	    (!req->child_slots && req->nr_child_slots))
		return -EINVAL;

	for (i = 0; i < req->nr_node_slots; i++) {
		if (req->node_slots[i].node ||
		    !__stack_depot_trie_pool_alloc_size(req->node_slots[i].size))
			return -EINVAL;
	}
	for (i = 0; i < req->nr_child_slots; i++) {
		if (req->child_slots[i].array ||
		    !trie_object_alloc_size(req->child_slots[i].size))
			return -EINVAL;
	}
	if (req->storage_size && !trie_object_alloc_size(req->storage_size))
		return -EINVAL;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return -EBUSY;
	printk_deferred_enter();
	if (!stack_pools) {
		ret = -ENOSPC;
		goto out;
	}
	trie_free_object_buckets_init_locked();
	trie_drain_pending_objects_locked();
	for (i = 0; i < req->nr_node_slots; i++) {
		req->node_slots[i].node = trie_pop_free_node(req->node_slots[i].size);
		if (!req->node_slots[i].node &&
		    trie_pool_add_size(req->node_slots[i].size, &total))
			goto out_release_reused;
	}
	for (i = 0; i < req->nr_child_slots; i++) {
		req->child_slots[i].array =
			trie_pop_free_object(req->child_slots[i].size);
		if (!req->child_slots[i].array &&
		    trie_pool_add_object_size(req->child_slots[i].size, &total))
			goto out_release_reused;
	}
	if (req->storage_size) {
		*req->storage = trie_pop_free_object(req->storage_size);
		if (!*req->storage && trie_pool_add_object_size(req->storage_size, &total))
			goto out_release_reused;
	}

	if (pools_num < 1) {
		req->mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->prealloc)) {
			ret = -ENOSPC;
			goto out_release_reused;
		}
		req->mark->added_pool = true;
	}
	if (WARN_ON_ONCE(pool_offset > DEPOT_POOL_SIZE))
		goto out_release_reused;
	if (total > DEPOT_POOL_SIZE - pool_offset) {
		req->mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->prealloc)) {
			ret = -ENOSPC;
			goto out_release_reused;
		}
		req->mark->added_pool = true;
	}

	req->mark->pool_index = pools_num - 1;
	pool = stack_pools[req->mark->pool_index];
	if (WARN_ON_ONCE(!pool))
		goto out_release_reused;

	req->mark->offset = pool_offset;
	req->mark->pool = pool;
	req->mark->size = total;
	offset = pool_offset;
	for (i = 0; i < req->nr_node_slots; i++) {
		if (req->node_slots[i].node)
			continue;
		req->node_slots[i].node = pool + offset;
		offset += __stack_depot_trie_pool_alloc_size(req->node_slots[i].size);
	}
	for (i = 0; i < req->nr_child_slots; i++) {
		if (req->child_slots[i].array)
			continue;
		req->child_slots[i].array =
			trie_object_init_fresh(pool + offset,
					       req->child_slots[i].size);
		offset += trie_object_alloc_size(req->child_slots[i].size);
	}
	if (req->storage_size && !*req->storage)
		*req->storage =
			trie_object_init_fresh(pool + offset, req->storage_size);
	pool_offset += total;
	ret = 0;
	goto out;
out_release_reused:
	trie_pool_release_reused_objects_locked(req);
out:
	printk_deferred_exit();
	raw_spin_unlock_irqrestore(&pool_lock, flags);
	return ret;
}

void __stack_depot_trie_alloc_txn_init(struct stack_depot_trie_alloc_txn *txn)
{
	if (txn)
		memset(txn, 0, sizeof(*txn));
}

int
__stack_depot_trie_alloc_txn_id(struct stack_depot_trie_alloc_txn *txn,
				struct stack_depot_trie_side_prealloc *prealloc)
{
	u32 leaf_id;

	if (!txn || txn->leaf_id)
		return -EINVAL;

	leaf_id = __stack_depot_trie_side_table_alloc_id(prealloc);
	if (!leaf_id)
		return -ENOSPC;

	txn->leaf_id = leaf_id;
	return 0;
}

static int trie_alloc_txn_id_trylock(struct stack_depot_trie_alloc_txn *txn)
{
	u32 leaf_id;

	if (!txn || txn->leaf_id)
		return -EINVAL;

	leaf_id = trie_side_table_alloc_id_trylock();
	if (!leaf_id)
		return -ENOSPC;

	txn->leaf_id = leaf_id;
	return 0;
}

static void trie_alloc_request_clear_outputs(struct stack_depot_trie_alloc_request *req)
{
	unsigned int i;

	if (!req)
		return;

	if (req->storage)
		*req->storage = NULL;
	for (i = 0; req->node_slots && i < req->nr_node_slots; i++)
		req->node_slots[i].node = NULL;
	for (i = 0; req->child_slots && i < req->nr_child_slots; i++)
		req->child_slots[i].array = NULL;
}

static void trie_alloc_request_release_reused_objects(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_request pool_req = {};

	if (!req || !req->txn)
		return;
	pool_req.node_slots = req->node_slots;
	pool_req.nr_node_slots = req->nr_node_slots;
	pool_req.child_slots = req->child_slots;
	pool_req.nr_child_slots = req->nr_child_slots;
	pool_req.storage = req->storage;
	pool_req.mark = &req->txn->pool;
	trie_pool_release_reused_objects(&pool_req);
}

int __stack_depot_trie_alloc_txn_reserve(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_request pool_req = {};
	int ret;

	if (!req || !req->txn)
		return -EINVAL;
	if (req->txn->leaf_id || req->txn->pool.size || req->txn->side.nr_updates)
		return -EINVAL;

	pool_req.node_slots = req->node_slots;
	pool_req.nr_node_slots = req->nr_node_slots;
	pool_req.child_slots = req->child_slots;
	pool_req.nr_child_slots = req->nr_child_slots;
	pool_req.storage = req->storage;
	pool_req.storage_size = req->storage_size;
	pool_req.prealloc = req->pool_prealloc;
	pool_req.mark = &req->txn->pool;

	ret = __stack_depot_trie_pool_carve(&pool_req);
	if (ret)
		return ret;

	ret = __stack_depot_trie_alloc_txn_id(req->txn, req->side_prealloc);
	if (ret) {
		trie_alloc_request_release_reused_objects(req);
		__stack_depot_trie_alloc_txn_rollback(req->txn);
		trie_alloc_request_clear_outputs(req);
		return ret;
	}

	return 0;
}

static void
trie_alloc_request_release_reused_objects_trylock(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_request pool_req = {};

	if (!req || !req->txn)
		return;
	pool_req.node_slots = req->node_slots;
	pool_req.nr_node_slots = req->nr_node_slots;
	pool_req.child_slots = req->child_slots;
	pool_req.nr_child_slots = req->nr_child_slots;
	pool_req.storage = req->storage;
	pool_req.mark = &req->txn->pool;
	trie_pool_release_reused_objects_trylock(&pool_req);
}

static void trie_alloc_txn_rollback_trylock(struct stack_depot_trie_alloc_txn *txn)
{
	if (!txn)
		return;

	if (txn->side.nr_updates)
		return;
	if (txn->leaf_id && trie_side_table_revoke_latest_trylock(txn->leaf_id))
		txn->leaf_id = 0;
	__stack_depot_trie_pool_try_rollback(&txn->pool);
	memset(&txn->pool, 0, sizeof(txn->pool));
}

static int trie_alloc_txn_reserve_trylock(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_request pool_req = {};
	int ret;

	if (!req || !req->txn)
		return -EINVAL;
	if (req->txn->leaf_id || req->txn->pool.size || req->txn->side.nr_updates)
		return -EINVAL;

	pool_req.node_slots = req->node_slots;
	pool_req.nr_node_slots = req->nr_node_slots;
	pool_req.child_slots = req->child_slots;
	pool_req.nr_child_slots = req->nr_child_slots;
	pool_req.storage = req->storage;
	pool_req.storage_size = req->storage_size;
	pool_req.prealloc = req->pool_prealloc;
	pool_req.mark = &req->txn->pool;

	ret = __stack_depot_trie_pool_carve(&pool_req);
	if (ret)
		return ret;

	ret = trie_alloc_txn_id_trylock(req->txn);
	if (ret) {
		trie_alloc_request_release_reused_objects_trylock(req);
		trie_alloc_txn_rollback_trylock(req->txn);
		trie_alloc_request_clear_outputs(req);
		return ret;
	}

	return 0;
}

int
__stack_depot_trie_alloc_txn_plan(const struct stack_depot_trie_root *root,
				  const unsigned long *entries,
				  unsigned int nr_entries,
				  struct stack_depot_trie_node_slot *node_slots,
				  unsigned int nr_node_slots,
				  struct stack_depot_trie_child_array_slot *child_slots,
				  unsigned int nr_child_slots,
				  struct stack_depot_trie_alloc_txn *txn,
				  void **storage, void **pool_prealloc,
				  struct stack_depot_trie_side_prealloc *side_prealloc,
				  struct stack_depot_trie_alloc_request *req)
{
	unsigned int nr_child_used;
	unsigned int nr_used;
	size_t storage_size;
	int ret;

	if (!root || !txn || !storage || !req)
		return -EINVAL;

	ret = __stack_depot_trie_insert_plan(root, NULL, entries, nr_entries,
					     node_slots, nr_node_slots, child_slots,
					     nr_child_slots, &storage_size, &nr_used,
					     &nr_child_used);
	if (ret)
		return ret;

	__stack_depot_trie_alloc_txn_init(txn);
	*storage = NULL;
	*req = (struct stack_depot_trie_alloc_request) {
		.txn = txn,
		.node_slots = node_slots,
		.child_slots = child_slots,
		.storage = storage,
		.pool_prealloc = pool_prealloc,
		.side_prealloc = side_prealloc,
		.storage_size = storage_size,
		.nr_node_slots = nr_used,
		.nr_child_slots = nr_child_used,
	};
	return 0;
}

static int
trie_ws_plan(const struct stack_depot_trie_root *root,
	     const unsigned long *entries, unsigned int nr_entries,
	     void **pool_prealloc,
	     struct stack_depot_trie_side_prealloc *side_prealloc,
	     struct stack_depot_trie_alloc_workspace *workspace)
{
	if (!workspace)
		return -EINVAL;

	memset(workspace, 0, sizeof(*workspace));
	return __stack_depot_trie_alloc_txn_plan(root, entries, nr_entries,
			workspace->node_slots, ARRAY_SIZE(workspace->node_slots),
			workspace->child_slots, ARRAY_SIZE(workspace->child_slots),
			&workspace->txn, &workspace->storage, pool_prealloc,
			side_prealloc, &workspace->req);
}

int __stack_depot_trie_workspace_plan(const struct stack_depot_trie_root *root,
				      const unsigned long *entries,
				      unsigned int nr_entries, void **pool_prealloc,
				      struct stack_depot_trie_side_prealloc *side_prealloc,
				      struct stack_depot_trie_alloc_workspace *workspace)
{
	return trie_ws_plan(root, entries, nr_entries, pool_prealloc, side_prealloc,
			    workspace);
}

int __stack_depot_trie_workspace_insert(struct stack_depot_trie_root *root,
					const unsigned long *entries,
					unsigned int nr_entries, void **pool_prealloc,
					struct stack_depot_trie_side_prealloc *side_prealloc,
					struct stack_depot_trie_alloc_workspace *workspace,
					const void **tail, u32 *leaf_id)
{
	void **pool = pool_prealloc;
	int ret;

	ret = trie_ws_plan(root, entries, nr_entries, pool, side_prealloc, workspace);
	if (ret)
		return ret;

	return __stack_depot_trie_alloc_txn_insert(root, &workspace->req, entries,
			nr_entries, workspace->scratch, ARRAY_SIZE(workspace->scratch),
			tail, leaf_id);
}

static int
trie_prealloc(gfp_t alloc_flags, depot_flags_t depot_flags,
	      void **pool_prealloc,
	      struct stack_depot_trie_side_prealloc *side_prealloc)
{
	return __stack_depot_trie_alloc_prealloc(alloc_flags, depot_flags,
					      pool_prealloc, side_prealloc);
}

static int trie_ws_insert(struct stack_depot_trie_root *root,
			  const unsigned long *entries, unsigned int nr_entries,
			  void **pool_prealloc,
			  struct stack_depot_trie_side_prealloc *side_prealloc,
			  struct stack_depot_trie_alloc_workspace *workspace,
			  const void **tail, u32 *leaf_id)
{
	return __stack_depot_trie_workspace_insert(root, entries, nr_entries,
					       pool_prealloc, side_prealloc,
					       workspace, tail, leaf_id);
}

static int trie_side_prepare_trylock(const struct stack_depot_trie_leaf_update *updates,
				     unsigned int nr_updates, void *ctx);

static int trie_ws_insert_trylock(struct stack_depot_trie_root *root,
				  const unsigned long *entries, unsigned int nr_entries,
				  struct stack_depot_trie_alloc_workspace *workspace,
				  const void **tail, u32 *leaf_id)
{
	struct stack_depot_trie_alloc_request *req = &workspace->req;
	struct stack_depot_trie_publish_prepare prepare;
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	void *pool_prealloc = NULL;
	unsigned long flags;
	unsigned long retire_flags;
	unsigned int nr_used;
	bool retire_locked = false;
	u32 id;
	int ret;

	if (!raw_spin_trylock_irqsave(&trie_alloc_lock, flags))
		return -EBUSY;

	ret = trie_ws_plan(root, entries, nr_entries, &pool_prealloc,
			   &side_prealloc, workspace);
	if (ret)
		goto out_unlock;
	if (pool_prealloc || side_prealloc.dir || side_prealloc.chunk) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = trie_alloc_txn_reserve_trylock(req);
	if (ret)
		goto out_unlock;
	if (!raw_spin_trylock_irqsave(&pool_lock, retire_flags)) {
		ret = -EBUSY;
		goto rollback;
	}
	retire_locked = true;

	prepare.fn = trie_side_prepare_trylock;
	prepare.ctx = &workspace->txn.side;
	prepare.retire_locked = true;
	id = workspace->txn.leaf_id;
	ret = __stack_depot_trie_insert_append_prepare(root, NULL, id, entries,
						       nr_entries, workspace->node_slots,
						       req->nr_node_slots, workspace->child_slots,
						       req->nr_child_slots, workspace->scratch,
						       ARRAY_SIZE(workspace->scratch),
						       workspace->storage, req->storage_size,
						       &prepare, tail, &nr_used);
	raw_spin_unlock_irqrestore(&pool_lock, retire_flags);
	retire_locked = false;
	if (ret)
		goto rollback;

	*leaf_id = __stack_depot_trie_alloc_txn_commit(&workspace->txn);
	ret = 0;
	goto out_unlock;

rollback:
	if (retire_locked)
		raw_spin_unlock_irqrestore(&pool_lock, retire_flags);
	trie_alloc_request_release_reused_objects_trylock(req);
	trie_alloc_txn_rollback_trylock(&workspace->txn);
	trie_alloc_request_clear_outputs(req);
	*tail = NULL;
out_unlock:
	raw_spin_unlock_irqrestore(&trie_alloc_lock, flags);
	return ret;
}

static depot_stack_handle_t
trie_find_handle(const struct stack_depot_trie_root *root,
		 const unsigned long *entries, unsigned int nr_entries)
{
	depot_stack_handle_t handle = 0;
	const struct stack_depot_trie_node *leaf;

	rcu_read_lock_sched_notrace();
	leaf = __stack_depot_trie_find_leaf(root, entries, nr_entries);
	if (leaf)
		handle = __stack_depot_trie_handle(leaf->leaf_id);
	rcu_read_unlock_sched_notrace();

	return handle;
}

static depot_stack_handle_t
trie_save_miss(struct stack_depot_trie_root *root, const unsigned long *entries,
	       unsigned int nr_entries, gfp_t alloc_flags,
	       depot_flags_t depot_flags,
	       struct stack_depot_trie_alloc_workspace *workspace)
{
	depot_stack_handle_t handle = 0;
	void *pool_prealloc = NULL;
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	const void *tail;
	u32 leaf_id;
	int ret;

	if (!root || !entries || !nr_entries || !workspace)
		return 0;
	if (depot_flags & STACK_DEPOT_FLAG_GET)
		return 0;
	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		return 0;
	if (in_nmi() || !gfpflags_allow_spinning(alloc_flags))
		return 0;

	ret = trie_prealloc(alloc_flags, depot_flags, &pool_prealloc,
			    &side_prealloc);
	if (ret)
		goto out;

	ret = trie_ws_insert(root, entries, nr_entries, &pool_prealloc,
			     &side_prealloc, workspace, &tail, &leaf_id);
	if (ret)
		goto out;

	handle = __stack_depot_trie_handle(leaf_id);
out:
	__stack_depot_trie_pool_free_prealloc(pool_prealloc);
	__stack_depot_trie_side_table_free_prealloc(&side_prealloc);
	return handle;
}

depot_stack_handle_t
__stack_depot_trie_save_miss(struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries,
			     gfp_t alloc_flags, depot_flags_t depot_flags,
			     struct stack_depot_trie_alloc_workspace *workspace)
{
	return trie_save_miss(root, entries, nr_entries, alloc_flags, depot_flags,
			      workspace);
}

depot_stack_handle_t
__stack_depot_trie_save(struct stack_depot_trie_root *root,
			const unsigned long *entries, unsigned int nr_entries,
			gfp_t alloc_flags, depot_flags_t depot_flags,
			struct stack_depot_trie_alloc_workspace *workspace)
{
	depot_stack_handle_t handle = 0;

	if (!root || !entries || !nr_entries || !workspace)
		return 0;
	if (depot_flags & STACK_DEPOT_FLAG_GET)
		return 0;
	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		return 0;

	handle = trie_find_handle(root, entries, nr_entries);
	if (handle)
		return handle;
	return trie_save_miss(root, entries, nr_entries, alloc_flags, depot_flags,
			      workspace);
}

static depot_stack_handle_t
trie_save_locked_insert(struct stack_depot_trie_root *root,
			const unsigned long *entries, unsigned int nr_entries,
			struct stack_depot_trie_alloc_workspace *workspace,
			void **pool_prealloc,
			struct stack_depot_trie_side_prealloc *side_prealloc,
			bool can_insert)
{
	depot_stack_handle_t handle;
	const void *tail;
	u32 leaf_id;
	int ret;

	handle = trie_find_handle(root, entries, nr_entries);
	if (!handle && can_insert) {
		ret = trie_ws_insert(root, entries, nr_entries, pool_prealloc,
				     side_prealloc, workspace, &tail, &leaf_id);
		if (!ret)
			handle = __stack_depot_trie_handle(leaf_id);
	}

	return handle;
}

static depot_stack_handle_t
trie_save_spinlocked(struct stack_depot_trie_root *root,
		     const unsigned long *entries, unsigned int nr_entries,
		     struct stack_depot_trie_alloc_workspace *workspace,
		     raw_spinlock_t *workspace_lock, void **pool_prealloc,
		     struct stack_depot_trie_side_prealloc *side_prealloc,
		     bool can_insert)
{
	depot_stack_handle_t handle;
	unsigned long flags;

	raw_spin_lock_irqsave(workspace_lock, flags);
	handle = trie_save_locked_insert(root, entries, nr_entries, workspace,
					 pool_prealloc, side_prealloc,
					 can_insert);
	raw_spin_unlock_irqrestore(workspace_lock, flags);
	return handle;
}

static depot_stack_handle_t
trie_save_trylocked(struct stack_depot_trie_root *root,
		    const unsigned long *entries, unsigned int nr_entries,
		    struct stack_depot_trie_alloc_workspace *workspace,
		    raw_spinlock_t *workspace_lock)
{
	depot_stack_handle_t handle = 0;
	unsigned long flags;
	const void *tail;
	u32 leaf_id;

	if (!raw_spin_trylock_irqsave(workspace_lock, flags))
		return 0;
	handle = trie_find_handle(root, entries, nr_entries);
	if (handle)
		goto out;
	if (!trie_ws_insert_trylock(root, entries, nr_entries, workspace, &tail,
				    &leaf_id))
		handle = __stack_depot_trie_handle(leaf_id);
out:
	raw_spin_unlock_irqrestore(workspace_lock, flags);
	return handle;
}

depot_stack_handle_t
__stack_depot_trie_save_locked(struct stack_depot_trie_root *root,
			       const unsigned long *entries, unsigned int nr_entries,
			       gfp_t alloc_flags, depot_flags_t depot_flags,
			       struct stack_depot_trie_alloc_workspace *workspace,
			       raw_spinlock_t *workspace_lock)
{
	depot_stack_handle_t handle = 0;
	void *pool_prealloc = NULL;
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	bool can_insert;
	bool no_spin;
	int ret;

	if (!root || !entries || !nr_entries || !workspace || !workspace_lock)
		return 0;
	if (depot_flags & STACK_DEPOT_FLAG_GET)
		return 0;
	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		return 0;

	handle = trie_find_handle(root, entries, nr_entries);
	if (handle)
		return handle;
	no_spin = in_nmi() || !gfpflags_allow_spinning(alloc_flags);
	if (no_spin)
		return trie_save_trylocked(root, entries, nr_entries, workspace,
					   workspace_lock);

	ret = trie_prealloc(alloc_flags, depot_flags, &pool_prealloc,
			    &side_prealloc);
	can_insert = !ret;
	handle = trie_save_spinlocked(root, entries, nr_entries, workspace,
				      workspace_lock, &pool_prealloc,
				      &side_prealloc, can_insert);

	depot_try_keep_new_pool(&pool_prealloc);
	__stack_depot_trie_pool_free_prealloc(pool_prealloc);
	__stack_depot_trie_side_table_free_prealloc(&side_prealloc);
	return handle;
}

u32 __stack_depot_trie_alloc_txn_commit(struct stack_depot_trie_alloc_txn *txn)
{
	u32 leaf_id;

	if (!txn)
		return 0;

	leaf_id = txn->leaf_id;
	__stack_depot_trie_alloc_txn_init(txn);
	return leaf_id;
}

int
__stack_depot_trie_alloc_txn_insert(struct stack_depot_trie_root *root,
				    struct stack_depot_trie_alloc_request *req,
				    const unsigned long *entries,
				    unsigned int nr_entries, u32 *scratch,
				    unsigned int nr_scratch, const void **tail,
				    u32 *leaf_id)
{
	struct stack_depot_trie_publish_prepare prepare;
	struct stack_depot_trie_alloc_txn *txn;
	unsigned long flags;
	u32 id;
	void *storage;
	unsigned int nr_used;
	int ret;

	if (!root || !req || !req->txn || !tail || !leaf_id)
		return -EINVAL;
	txn = req->txn;
	*tail = NULL;
	*leaf_id = 0;

	if (!raw_spin_trylock_irqsave(&trie_alloc_lock, flags))
		return -EBUSY;

	ret = __stack_depot_trie_alloc_txn_reserve(req);
	if (ret)
		goto out_unlock;
	storage = req->storage ? *req->storage : NULL;

	prepare.fn = __stack_depot_trie_side_prepare;
	prepare.ctx = &txn->side;
	prepare.retire_locked = false;
	id = txn->leaf_id;
	ret = __stack_depot_trie_insert_append_prepare(root, NULL, id, entries,
						       nr_entries, req->node_slots,
						       req->nr_node_slots, req->child_slots,
						       req->nr_child_slots, scratch,
						       nr_scratch, storage, req->storage_size,
						       &prepare, tail, &nr_used);
	if (ret)
		goto rollback;

	*leaf_id = __stack_depot_trie_alloc_txn_commit(txn);
	ret = 0;
	goto out_unlock;

rollback:
	trie_alloc_request_release_reused_objects(req);
	__stack_depot_trie_alloc_txn_rollback(req->txn);
	trie_alloc_request_clear_outputs(req);
	*tail = NULL;
out_unlock:
	raw_spin_unlock_irqrestore(&trie_alloc_lock, flags);
	return ret;
}

void __stack_depot_trie_alloc_txn_rollback(struct stack_depot_trie_alloc_txn *txn)
{
	if (!txn)
		return;

	__stack_depot_trie_side_rollback(&txn->side);
	if (txn->leaf_id) {
		__stack_depot_trie_side_table_revoke_latest(txn->leaf_id);
		txn->leaf_id = 0;
	}
	__stack_depot_trie_pool_try_rollback(&txn->pool);
	memset(&txn->pool, 0, sizeof(txn->pool));
}

void __stack_depot_trie_side_prepare_init(struct stack_depot_trie_side_prepare *state)
{
	if (state)
		memset(state, 0, sizeof(*state));
}

void __stack_depot_trie_side_rollback(struct stack_depot_trie_side_prepare *state)
{
	if (!state)
		return;

	while (state->nr_updates) {
		struct stack_depot_trie_side_checkpoint *update;

		state->nr_updates--;
		update = &state->updates[state->nr_updates];
		__stack_depot_trie_side_table_restore(update->leaf_id, update->old_leaf);
	}
}

static int
trie_side_prepare_locked(const struct stack_depot_trie_leaf_update *updates,
			 unsigned int nr_updates,
			 struct stack_depot_trie_side_prepare *state)
{
	struct stack_depot_trie_side_entry *chunks[STACK_DEPOT_TRIE_MAX_LEAF_UPDATES];
	unsigned int slots[STACK_DEPOT_TRIE_MAX_LEAF_UPDATES];
	unsigned int i;

	lockdep_assert_held(&trie_side_table_lock);
	if (!state || (!updates && nr_updates))
		return -EINVAL;
	if (nr_updates > ARRAY_SIZE(chunks) ||
	    state->nr_updates > ARRAY_SIZE(state->updates) - nr_updates)
		return -EINVAL;

	for (i = 0; i < nr_updates; i++) {
		u32 leaf_id = updates[i].leaf_id;

		if (!updates[i].leaf)
			return -EINVAL;
		chunks[i] = trie_side_table_chunk_locked(leaf_id, &slots[i]);
		if (!chunks[i])
			return -EINVAL;
	}

	for (i = 0; i < nr_updates; i++) {
		state->updates[state->nr_updates].leaf_id = updates[i].leaf_id;
		state->updates[state->nr_updates].old_leaf =
			trie_side_table_load_leaf(chunks[i], slots[i]);
		state->nr_updates++;
		trie_side_table_store_leaf(chunks[i], slots[i], updates[i].leaf);
	}

	return 0;
}

int
__stack_depot_trie_side_prepare(const struct stack_depot_trie_leaf_update *updates,
				unsigned int nr_updates, void *ctx)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	ret = trie_side_prepare_locked(updates, nr_updates, ctx);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return ret;
}

static int
trie_side_prepare_trylock(const struct stack_depot_trie_leaf_update *updates,
			  unsigned int nr_updates, void *ctx)
{
	unsigned long flags;
	int ret;

	if (!raw_spin_trylock_irqsave(&trie_side_table_lock, flags))
		return -EBUSY;
	ret = trie_side_prepare_locked(updates, nr_updates, ctx);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return ret;
}

static int __init disable_stack_depot(char *str)
{
	return kstrtobool(str, &stack_depot_disabled);
}
early_param("stack_depot_disable", disable_stack_depot);

static int __init parse_max_pools(char *str)
{
	const long long limit = (1LL << (DEPOT_POOL_INDEX_BITS)) - 1;
	unsigned int max_pools;
	int rv;

	rv = kstrtouint(str, 0, &max_pools);
	if (rv)
		return rv;

	if (max_pools < 1024) {
		pr_err("stack_depot_max_pools below 1024, using default of %u\n",
		       stack_max_pools);
		goto out;
	}

	if (max_pools > limit) {
		pr_err("stack_depot_max_pools exceeds %lld, using default of %u\n",
		       limit, stack_max_pools);
		goto out;
	}

	stack_max_pools = max_pools;
out:
	return 0;
}
early_param("stack_depot_max_pools", parse_max_pools);

void __init stack_depot_request_early_init(void)
{
	/* Too late to request early init now. */
	WARN_ON(__stack_depot_early_init_passed);

	__stack_depot_early_init_requested = true;
}

/* Initialize list_head's within the hash table. */
static void init_stack_table(unsigned long entries)
{
	unsigned long i;

	for (i = 0; i < entries; i++)
		INIT_LIST_HEAD(&stack_table[i]);
}

/* Allocates a hash table via memblock. Can only be used during early boot. */
int __init stack_depot_early_init(void)
{
	unsigned long entries = 0;
	unsigned long min = 1UL << STACK_BUCKET_NUMBER_ORDER_MIN;
	unsigned long max = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;

	/* This function must be called only once, from mm_init(). */
	if (WARN_ON(__stack_depot_early_init_passed))
		return 0;
	__stack_depot_early_init_passed = true;

	/*
	 * Print disabled message even if early init has not been requested:
	 * stack_depot_init() will not print one.
	 */
	if (stack_depot_disabled) {
		pr_info("disabled\n");
		return 0;
	}

	/*
	 * If KASAN is enabled, use the maximum order: KASAN is frequently used
	 * in fuzzing scenarios, which leads to a large number of different
	 * stack traces being stored in stack depot.
	 */
	if (kasan_enabled() && !stack_bucket_number_order)
		stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;

	/*
	 * Check if early init has been requested after setting
	 * stack_bucket_number_order: stack_depot_init() uses its value.
	 */
	if (!__stack_depot_early_init_requested)
		return 0;

	/*
	 * If stack_bucket_number_order is not set, leave entries as 0 to rely
	 * on the automatic calculations performed by alloc_large_system_hash().
	 */
	if (stack_bucket_number_order)
		entries = 1UL << stack_bucket_number_order;
	pr_info("allocating hash table via alloc_large_system_hash\n");
	stack_table = alloc_large_system_hash("stackdepot", sizeof(*stack_table),
					      entries, STACK_HASH_TABLE_SCALE,
					      HASH_EARLY, NULL, &stack_hash_mask,
					      min, max);
	if (!stack_table) {
		pr_err("hash table allocation failed, disabling\n");
		stack_depot_disabled = true;
		return -ENOMEM;
	}
	if (!entries) {
		/*
		 * Obtain the number of entries that was calculated by
		 * alloc_large_system_hash().
		 */
		entries = stack_hash_mask + 1;
	}
	init_stack_table(entries);

	pr_info("allocating space for %u stack pools via memblock\n",
		stack_max_pools);
	stack_pools =
		memblock_alloc(stack_max_pools * sizeof(void *), PAGE_SIZE);
	if (!stack_pools) {
		pr_err("stack pools allocation failed, disabling\n");
		memblock_free(stack_table, entries * sizeof(struct list_head));
		stack_depot_disabled = true;
		return -ENOMEM;
	}
	if (__stack_depot_trie_enabled() && stack_depot_trie_init_memblock()) {
		pr_warn("trie storage initialization failed, disabling trie storage\n");
		__stack_depot_trie_set_enabled(false);
	}

	return 0;
}

/* Allocates a hash table via kvcalloc. Can be used after boot. */
int stack_depot_init(void)
{
	static DEFINE_MUTEX(stack_depot_init_mutex);
	unsigned long entries;
	int ret = 0;

	mutex_lock(&stack_depot_init_mutex);

	if (stack_depot_disabled)
		goto out_unlock;
	if (stack_table)
		goto init_trie;

	/*
	 * Similarly to stack_depot_early_init, use stack_bucket_number_order
	 * if assigned, and rely on automatic scaling otherwise.
	 */
	if (stack_bucket_number_order) {
		entries = 1UL << stack_bucket_number_order;
	} else {
		int scale = STACK_HASH_TABLE_SCALE;

		entries = nr_free_buffer_pages();
		entries = roundup_pow_of_two(entries);

		if (scale > PAGE_SHIFT)
			entries >>= (scale - PAGE_SHIFT);
		else
			entries <<= (PAGE_SHIFT - scale);
	}

	if (entries < 1UL << STACK_BUCKET_NUMBER_ORDER_MIN)
		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MIN;
	if (entries > 1UL << STACK_BUCKET_NUMBER_ORDER_MAX)
		entries = 1UL << STACK_BUCKET_NUMBER_ORDER_MAX;

	pr_info("allocating hash table of %lu entries via kvcalloc\n", entries);
	stack_table = kvcalloc(entries, sizeof(struct list_head), GFP_KERNEL);
	if (!stack_table) {
		pr_err("hash table allocation failed, disabling\n");
		stack_depot_disabled = true;
		ret = -ENOMEM;
		goto out_unlock;
	}
	stack_hash_mask = entries - 1;
	init_stack_table(entries);

	pr_info("allocating space for %u stack pools via kvcalloc\n",
		stack_max_pools);
	stack_pools = kvcalloc(stack_max_pools, sizeof(void *), GFP_KERNEL);
	if (!stack_pools) {
		pr_err("stack pools allocation failed, disabling\n");
		kvfree(stack_table);
		stack_table = NULL;
		stack_hash_mask = 0;
		stack_depot_disabled = true;
		ret = -ENOMEM;
		goto out_unlock;
	}
init_trie:
	if (!ret && __stack_depot_trie_enabled()) {
		ret = stack_depot_trie_init(GFP_KERNEL);
		if (ret) {
			pr_warn("trie storage initialization failed, disabling trie storage\n");
			__stack_depot_trie_set_enabled(false);
			ret = 0;
		}
	}

out_unlock:
	mutex_unlock(&stack_depot_init_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(stack_depot_init);

/*
 * Initializes new stack pool, and updates the list of pools.
 */
static bool depot_init_pool(void **prealloc)
{
	lockdep_assert_held(&pool_lock);

	if (unlikely(pools_num >= stack_max_pools)) {
		/* Bail out if we reached the pool limit. */
		WARN_ON_ONCE(pools_num > stack_max_pools); /* should never happen */
		WARN_ON_ONCE(!new_pool); /* to avoid unnecessary pre-allocation */
		WARN_ONCE(1, "Stack depot reached limit capacity");
		return false;
	}

	/* Trie allocation probes may intentionally call without a preallocation. */
	if (!new_pool && prealloc && *prealloc) {
		/* We have preallocated memory, use it. */
		WRITE_ONCE(new_pool, *prealloc);
		*prealloc = NULL;
	}

	if (!new_pool)
		return false; /* new_pool and *prealloc are NULL */

	/* Save reference to the pool to be used by depot_fetch_stack(). */
	stack_pools[pools_num] = new_pool;
	depot_record_pool_locked(new_pool);

	/*
	 * Stack depot tries to keep an extra pool allocated even before it runs
	 * out of space in the currently used pool.
	 *
	 * To indicate that a new preallocation is needed new_pool is reset to
	 * NULL; do not reset to NULL if we have reached the maximum number of
	 * pools.
	 */
	if (pools_num < stack_max_pools)
		WRITE_ONCE(new_pool, NULL);
	else
		WRITE_ONCE(new_pool, STACK_DEPOT_POISON);

	/* Pairs with concurrent READ_ONCE() in depot_fetch_stack(). */
	WRITE_ONCE(pools_num, pools_num + 1);
	ASSERT_EXCLUSIVE_WRITER(pools_num);

	pool_offset = 0;

	return true;
}

/* Keeps the preallocated memory to be used for a new stack depot pool. */
static void depot_keep_new_pool(void **prealloc)
{
	lockdep_assert_held(&pool_lock);

	/*
	 * If a new pool is already saved or the maximum number of
	 * pools is reached, do not use the preallocated memory.
	 */
	if (new_pool)
		return;

	WRITE_ONCE(new_pool, *prealloc);
	*prealloc = NULL;
}

static void depot_try_keep_new_pool(void **prealloc)
{
	unsigned long flags;

	if (!prealloc || !*prealloc)
		return;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return;
	depot_keep_new_pool(prealloc);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

/*
 * Try to initialize a new stack record from the current pool, a cached pool, or
 * the current pre-allocation.
 */
static struct stack_record *depot_pop_free_pool(void **prealloc, size_t size)
{
	struct stack_record *stack;
	void *current_pool;
	u32 pool_index;

	lockdep_assert_held(&pool_lock);

	if (pool_offset + size > DEPOT_POOL_SIZE) {
		if (!depot_init_pool(prealloc))
			return NULL;
	}

	if (WARN_ON_ONCE(pools_num < 1))
		return NULL;
	pool_index = pools_num - 1;
	current_pool = stack_pools[pool_index];
	if (WARN_ON_ONCE(!current_pool))
		return NULL;

	stack = current_pool + pool_offset;

	/* Pre-initialize handle once. */
	stack->handle.pool_index_plus_1 = pool_index + 1;
	stack->handle.offset = pool_offset >> DEPOT_STACK_ALIGN;
	stack->handle.extra = 0;
	INIT_LIST_HEAD(&stack->hash_list);

	pool_offset += size;

	return stack;
}

/* Try to find next free usable entry from the freelist. */
static struct stack_record *depot_pop_free(void)
{
	struct stack_record *stack;

	lockdep_assert_held(&pool_lock);

	if (list_empty(&free_stacks))
		return NULL;

	/*
	 * We maintain the invariant that the elements in front are least
	 * recently used, and are therefore more likely to be associated with an
	 * RCU grace period in the past. Consequently it is sufficient to only
	 * check the first entry.
	 */
	stack = list_first_entry(&free_stacks, struct stack_record, free_list);
	if (!poll_state_synchronize_rcu(stack->rcu_state))
		return NULL;

	list_del(&stack->free_list);
	counters[DEPOT_COUNTER_FREELIST_SIZE]--;

	return stack;
}

static inline size_t depot_stack_record_size(struct stack_record *s, unsigned int nr_entries)
{
	const size_t used = flex_array_size(s, entries, nr_entries);
	const size_t unused = sizeof(s->entries) - used;

	WARN_ON_ONCE(sizeof(s->entries) < used);

	return ALIGN(sizeof(struct stack_record) - unused, 1 << DEPOT_STACK_ALIGN);
}

/* Allocates a new stack in a stack depot pool. */
static struct stack_record *
depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash,
		  depot_flags_t flags, void **prealloc)
{
	struct stack_record *stack = NULL;
	size_t record_size;

	lockdep_assert_held(&pool_lock);

	/* This should already be checked by public API entry points. */
	if (WARN_ON_ONCE(!nr_entries))
		return NULL;

	/* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. */
	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;

	if (flags & STACK_DEPOT_FLAG_GET) {
		/*
		 * Evictable entries have to allocate the max. size so they may
		 * safely be re-used by differently sized allocations.
		 */
		record_size = depot_stack_record_size(stack, CONFIG_STACKDEPOT_MAX_FRAMES);
		stack = depot_pop_free();
	} else {
		record_size = depot_stack_record_size(stack, nr_entries);
	}

	if (!stack) {
		stack = depot_pop_free_pool(prealloc, record_size);
		if (!stack)
			return NULL;
	}

	/* Save the stack trace. */
	stack->hash = hash;
	stack->size = nr_entries;
	/* stack->handle is already filled in by depot_pop_free_pool(). */
	memcpy(stack->entries, entries, flex_array_size(stack, entries, nr_entries));

	if (flags & STACK_DEPOT_FLAG_GET) {
		refcount_set(&stack->count, 1);
		counters[DEPOT_COUNTER_REFD_ALLOCS]++;
		counters[DEPOT_COUNTER_REFD_INUSE]++;
	} else {
		/* Warn on attempts to switch to refcounting this entry. */
		refcount_set(&stack->count, REFCOUNT_SATURATED);
		counters[DEPOT_COUNTER_PERSIST_COUNT]++;
		counters[DEPOT_COUNTER_PERSIST_BYTES] += record_size;
	}

	/*
	 * Let KMSAN know the stored stack record is initialized. This shall
	 * prevent false positive reports if instrumented code accesses it.
	 */
	kmsan_unpoison_memory(stack, record_size);

	return stack;
}

static struct stack_record *depot_fetch_stack(depot_stack_handle_t handle)
{
	const int pools_num_cached = READ_ONCE(pools_num);
	union handle_parts parts = { .handle = handle };
	void *pool;
	u32 pool_index = parts.pool_index_plus_1 - 1;
	size_t offset = parts.offset << DEPOT_STACK_ALIGN;
	struct stack_record *stack;

	lockdep_assert_not_held(&pool_lock);

	if (pool_index >= pools_num_cached) {
		WARN(1, "pool index %d out of bounds (%d) for stack id %08x\n",
		     pool_index, pools_num_cached, handle);
		return NULL;
	}

	pool = stack_pools[pool_index];
	if (WARN_ON(!pool))
		return NULL;

	stack = pool + offset;
	if (WARN_ON(!refcount_read(&stack->count)))
		return NULL;

	return stack;
}

/* Links stack into the freelist. */
static void depot_free_stack(struct stack_record *stack)
{
	unsigned long flags;

	lockdep_assert_not_held(&pool_lock);

	raw_spin_lock_irqsave(&pool_lock, flags);
	printk_deferred_enter();

	/*
	 * Remove the entry from the hash list. Concurrent list traversal may
	 * still observe the entry, but since the refcount is zero, this entry
	 * will no longer be considered as valid.
	 */
	list_del_rcu(&stack->hash_list);

	/*
	 * Due to being used from constrained contexts such as the allocators,
	 * NMI, or even RCU itself, stack depot cannot rely on primitives that
	 * would sleep (such as synchronize_rcu()) or recursively call into
	 * stack depot again (such as call_rcu()).
	 *
	 * Instead, get an RCU cookie, so that we can ensure this entry isn't
	 * moved onto another list until the next grace period, and concurrent
	 * RCU list traversal remains safe.
	 */
	stack->rcu_state = get_state_synchronize_rcu();

	/*
	 * Add the entry to the freelist tail, so that older entries are
	 * considered first - their RCU cookie is more likely to no longer be
	 * associated with the current grace period.
	 */
	list_add_tail(&stack->free_list, &free_stacks);

	counters[DEPOT_COUNTER_FREELIST_SIZE]++;
	counters[DEPOT_COUNTER_REFD_FREES]++;
	counters[DEPOT_COUNTER_REFD_INUSE]--;

	printk_deferred_exit();
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

/* Calculates the hash for a stack. */
static inline u32 hash_stack(unsigned long *entries, unsigned int size)
{
	return jhash2((u32 *)entries,
		      array_size(size,  sizeof(*entries)) / sizeof(u32),
		      STACK_HASH_SEED);
}

/*
 * Non-instrumented version of memcmp().
 * Does not check the lexicographical order, only the equality.
 */
static inline int stackdepot_memcmp(const unsigned long *u1,
				    const unsigned long *u2, unsigned int n)
{
	for ( ; n-- ; u1++, u2++) {
		if (*u1 != *u2)
			return 1;
	}
	return 0;
}

/* Finds a stack in a bucket of the hash table. */
static inline struct stack_record *find_stack(struct list_head *bucket,
					      unsigned long *entries, int size,
					      u32 hash, depot_flags_t flags)
{
	struct stack_record *stack, *ret = NULL;

	/*
	 * Stack depot may be used from instrumentation that instruments RCU or
	 * tracing itself; use variant that does not call into RCU and cannot be
	 * traced.
	 *
	 * Note: Such use cases must take care when using refcounting to evict
	 * unused entries, because the stack record free-then-reuse code paths
	 * do call into RCU.
	 */
	rcu_read_lock_sched_notrace();

	list_for_each_entry_rcu(stack, bucket, hash_list) {
		if (stack->hash != hash || stack->size != size)
			continue;

		/*
		 * This may race with depot_free_stack() accessing the freelist
		 * management state unioned with @entries. The refcount is zero
		 * in that case and the below refcount_inc_not_zero() will fail.
		 */
		if (data_race(stackdepot_memcmp(entries, stack->entries, size)))
			continue;

		/*
		 * Try to increment refcount. If this succeeds, the stack record
		 * is valid and has not yet been freed.
		 *
		 * If STACK_DEPOT_FLAG_GET is not used, it is undefined behavior
		 * to then call stack_depot_put() later, and we can assume that
		 * a stack record is never placed back on the freelist.
		 */
		if ((flags & STACK_DEPOT_FLAG_GET) && !refcount_inc_not_zero(&stack->count))
			continue;

		ret = stack;
		break;
	}

	rcu_read_unlock_sched_notrace();

	return ret;
}

static depot_stack_handle_t
stack_depot_trie_save(unsigned long *entries, unsigned int nr_entries,
		      gfp_t alloc_flags, depot_flags_t depot_flags)
{
	return __stack_depot_trie_save_locked(&stack_depot_trie_root, entries,
					   nr_entries, alloc_flags, depot_flags,
					   stack_depot_trie_workspace,
					   &stack_depot_trie_workspace_lock);
}

struct stack_depot_hash_save {
	struct list_head *bucket;
	unsigned long *entries;
	unsigned int nr_entries;
	u32 hash;
	depot_flags_t depot_flags;
	void **prealloc;
	bool normal_persistent;
};

static depot_stack_handle_t
depot_save_stack_locked(struct stack_depot_hash_save *save)
{
	struct stack_record *found;
	struct stack_record *new;

	lockdep_assert_held(&pool_lock);

	/* Try to find again, to avoid concurrently inserting duplicates. */
	found = find_stack(save->bucket, save->entries, save->nr_entries,
			   save->hash, save->depot_flags);
	if (found)
		return found->handle.handle;

	new = depot_alloc_stack(save->entries, save->nr_entries, save->hash,
				save->depot_flags, save->prealloc);
	if (!new)
		return 0;

	/*
	 * This releases the stack record into the bucket and makes it visible to
	 * readers in find_stack().
	 */
	list_add_rcu(&new->hash_list, save->bucket);
	if (save->normal_persistent)
		WRITE_ONCE(stack_depot_persistent_hash_record_seen, true);

	return new->handle.handle;
}

depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
					    unsigned int nr_entries,
					    gfp_t alloc_flags,
					    depot_flags_t depot_flags)
{
	struct list_head *bucket;
	struct stack_depot_hash_save save;
	struct stack_record *found = NULL;
	depot_stack_handle_t handle = 0;
	struct page *page = NULL;
	void *prealloc = NULL;
	bool allow_spin = gfpflags_allow_spinning(alloc_flags);
	bool can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) && allow_spin;
	bool normal_persistent;
	bool trie_candidate;
	unsigned long flags;
	u32 hash;

	if (WARN_ON(depot_flags & ~STACK_DEPOT_FLAGS_MASK))
		return 0;

	/*
	 * If this stack trace is from an interrupt, including anything before
	 * interrupt entry usually leads to unbounded stack depot growth.
	 *
	 * Since use of filter_irq_stacks() is a requirement to ensure stack
	 * depot can efficiently deduplicate interrupt stacks, always
	 * filter_irq_stacks() to simplify all callers' use of stack depot.
	 */
	nr_entries = filter_irq_stacks(entries, nr_entries);

	if (unlikely(nr_entries == 0) || stack_depot_disabled)
		return 0;
	normal_persistent = !(depot_flags & (STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_HASH)) &&
		nr_entries <= CONFIG_STACKDEPOT_MAX_FRAMES;

	trie_candidate = normal_persistent && __stack_depot_trie_ready();
	if (trie_candidate) {
		if (READ_ONCE(stack_depot_persistent_hash_record_seen)) {
			/*
			 * Trie storage may be enabled after stack depot has already saved
			 * hash records. Preserve the same-handle contract by checking hash
			 * only when such records may exist.
			 */
			hash = hash_stack(entries, nr_entries);
			bucket = &stack_table[hash & stack_hash_mask];
			found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
			if (found)
				return found->handle.handle;
		}

		handle = stack_depot_trie_save(entries, nr_entries, alloc_flags,
					       depot_flags);
		if (handle)
			return handle;
		return 0;
	}

	hash = hash_stack(entries, nr_entries);
	bucket = &stack_table[hash & stack_hash_mask];
	save = (struct stack_depot_hash_save) {
		.bucket = bucket,
		.entries = entries,
		.nr_entries = nr_entries,
		.hash = hash,
		.depot_flags = depot_flags,
		.prealloc = &prealloc,
		.normal_persistent = normal_persistent,
	};

	/* Fast path: look the stack trace up without locking. */
	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
	if (found)
		return found->handle.handle;
	/*
	 * Allocate memory for a new pool if required now:
	 * we won't be able to do that under the lock.
	 */
	if (unlikely(can_alloc && !READ_ONCE(new_pool))) {
		page = alloc_pages(gfp_nested_mask(alloc_flags),
				   DEPOT_POOL_ORDER);
		if (page)
			prealloc = page_address(page);
	}

	if (in_nmi() || !allow_spin) {
		/* We can never allocate in NMI context. */
		WARN_ON_ONCE(can_alloc);
		/* Best effort; bail if we fail to take the lock. */
		if (!raw_spin_trylock_irqsave(&pool_lock, flags))
			goto out_free;
		printk_deferred_enter();
		handle = depot_save_stack_locked(&save);
		if (prealloc) {
			/*
			 * Either stack depot already contains this stack trace, or
			 * depot_alloc_stack() did not consume the preallocated memory.
			 * Try to keep the preallocated memory for future.
			 */
			depot_keep_new_pool(&prealloc);
		}
		printk_deferred_exit();
		raw_spin_unlock_irqrestore(&pool_lock, flags);
		goto out_free;
	}

	raw_spin_lock_irqsave(&pool_lock, flags);
	printk_deferred_enter();
	handle = depot_save_stack_locked(&save);
	if (prealloc) {
		/*
		 * Either stack depot already contains this stack trace, or
		 * depot_alloc_stack() did not consume the preallocated memory.
		 * Try to keep the preallocated memory for future.
		 */
		depot_keep_new_pool(&prealloc);
	}
	printk_deferred_exit();
	raw_spin_unlock_irqrestore(&pool_lock, flags);

out_free:
	if (prealloc) {
		/* Stack depot didn't use this memory, free it. */
		free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
	}
	return handle;
}
EXPORT_SYMBOL_GPL(stack_depot_save_flags);

depot_stack_handle_t stack_depot_save(unsigned long *entries,
				      unsigned int nr_entries,
				      gfp_t alloc_flags)
{
	return stack_depot_save_flags(entries, nr_entries, alloc_flags,
				      STACK_DEPOT_FLAG_CAN_ALLOC);
}
EXPORT_SYMBOL_GPL(stack_depot_save);

bool __stack_depot_get_count(depot_stack_handle_t handle, unsigned int *count)
{
	struct stack_record *stack;
	unsigned int raw;

	if (!handle || !count)
		return false;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return false;

	/* Negative saturated counts wrap above INT_MAX when converted to unsigned. */
	raw = (unsigned int)refcount_read(&stack->count);
	/* Saturated and zero records are not in counted mode. */
	if (!raw || raw > INT_MAX)
		return false;

	*count = raw;
	return true;
}

void __stack_depot_set_count(depot_stack_handle_t handle, unsigned int count)
{
	struct stack_record *stack;

	/* Reject values outside positive refcount space. */
	if (!handle || !count || count > (unsigned int)INT_MAX)
		return;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return;

	refcount_set(&stack->count, (int)count);
}

bool __stack_depot_inc_count(depot_stack_handle_t handle,
			     unsigned int count,
			     bool *new_count)
{
	struct stack_record *stack;
	int new;
	int old = REFCOUNT_SATURATED;
	bool was_saturated = false;

	if (new_count)
		*new_count = false;
	if (!handle || !count || count > (unsigned int)INT_MAX - 1)
		return false;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return false;

	new = 1 + (int)count;
	/*
	 * Intentional refcount_t internals use: no helper conditionally
	 * converts the persistent REFCOUNT_SATURATED sentinel to a positive
	 * page_owner count. The first cmpxchg only performs that one-way
	 * transition; normal counted records continue through a checked cmpxchg
	 * loop so overflow cannot recreate the saturated sentinel.
	 */
	if (atomic_try_cmpxchg(&stack->count.refs, &old, new)) {
		was_saturated = true;
	} else {
		/* cmpxchg reloads @old before each retry check. */
		do {
			if (old <= 0)
				return false;
			if (count > (unsigned int)INT_MAX - (unsigned int)old)
				return false;
			new = old + (int)count;
		} while (!atomic_try_cmpxchg(&stack->count.refs, &old, new));
	}

	if (new_count)
		*new_count = was_saturated;
	return true;
}

bool __stack_depot_dec_count_and_test(depot_stack_handle_t handle,
				      unsigned int count)
{
	struct stack_record *stack;
	int new;
	int old;

	if (!handle || !count || count > (unsigned int)INT_MAX)
		return false;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return false;

	/*
	 * Intentional refcount_t internals use: refcount_sub_and_test() would
	 * saturate on underflow, but page_owner accounting must warn and leave
	 * the existing count unchanged.
	 */
	/* The first cmpxchg failure reloads @old before retry checks. */
	old = INT_MAX;
	do {
		bool underflow;

		/*
		 * Retry checks use the observed count as this operation's
		 * linearization point. A racing increment not observed here is
		 * ordered after this decrement.
		 */
		/* Saturated counts are negative and intentionally fail closed here. */
		if (old <= 0)
			return false;

		underflow = count > (unsigned int)old;
		if (underflow) {
			WARN_RATELIMIT(underflow, "stack depot count underflow\n");
			return false;
		}

		new = old - (int)count;
	} while (!atomic_try_cmpxchg_release(&stack->count.refs, &old, new));

	/* Non-zero results are diagnostic counts; callers consume no ordered data. */
	if (!new)
		smp_acquire__after_ctrl_dep();

	return !new;
}

static bool frame_try_compress(unsigned long frame, u8 *prefix_id, u32 *low)
{
	if (!prefix_id || !low)
		return false;

	return arch_stack_depot_frame_try_compress(frame, prefix_id, low);
}

bool __stack_depot_frame_try_compress(unsigned long frame, u8 *prefix_id,
				      u32 *low)
{
	return frame_try_compress(frame, prefix_id, low);
}

static bool frame_decompress(u8 prefix_id, u32 low, unsigned long *frame)
{
	if (!frame)
		return false;

	return arch_stack_depot_frame_decompress(prefix_id, low, frame);
}

bool __stack_depot_frame_decompress(u8 prefix_id, u32 low,
				    unsigned long *frame)
{
	return frame_decompress(prefix_id, low, frame);
}

static bool stack_depot_ranges_overlap(const void *a, size_t a_size,
				       const void *b, size_t b_size);
static int
stack_depot_trie_child_lower_bound(const struct stack_depot_trie_child_array *array,
				   unsigned long frame, unsigned int *pos,
				   bool *found);
static unsigned int trie_child_array_storage_capacity(size_t storage_size);
static size_t trie_child_array_size_for_capacity(unsigned int capacity);
static bool
trie_parent_chain_matches_prefix(const struct stack_depot_trie_node *node,
				 const unsigned long *entries,
				 unsigned int nr_entries);

static size_t stack_depot_frame_run_entry_bytes(enum stack_depot_frame_mode mode)
{
	if (mode == STACK_DEPOT_FRAME_COMPRESSED)
		return sizeof(u32);
	return sizeof(unsigned long);
}

static int stack_depot_frame_run_validate(const struct stack_depot_frame_run *run)
{
	size_t bytes;

	if (!run || !run->nr_entries ||
	    run->nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		return -EINVAL;

	switch (run->mode) {
	case STACK_DEPOT_FRAME_RAW:
	case STACK_DEPOT_FRAME_COMPRESSED:
		break;
	default:
		return -EINVAL;
	}

	bytes = run->nr_entries * stack_depot_frame_run_entry_bytes(run->mode);
	if (run->bytes != bytes)
		return -EINVAL;

	return 0;
}

static int frame_run_init_lows(const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_frame_run *run,
			       u32 *lows, unsigned int nr_lows)
{
	u8 first_prefix = 0;
	u32 low;
	unsigned int i;
	bool compressed;

	if (!entries || !nr_entries || !run ||
	    nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		return -EINVAL;
	/* The run length is not known yet, so scratch must cover the input. */
	if (lows && nr_entries > nr_lows)
		return -EINVAL;

	/* On compressed success, only lows[0..run->nr_entries - 1] are initialized. */
	/* Only prefix ids classify a run; low bits are scratch for the arch hook. */
	compressed = frame_try_compress(entries[0], &first_prefix, &low);
	if (compressed && lows)
		lows[0] = low;
	for (i = 1; i < nr_entries; i++) {
		u8 prefix_id;
		bool next;

		next = frame_try_compress(entries[i], &prefix_id, &low);
		if (next != compressed)
			break;
		if (compressed && prefix_id != first_prefix)
			break;
		if (compressed && lows)
			lows[i] = low;
	}

	/* @i is the first non-matching frame, or @nr_entries if all matched. */
	run->mode = compressed ? STACK_DEPOT_FRAME_COMPRESSED : STACK_DEPOT_FRAME_RAW;
	run->prefix_id = compressed ? first_prefix : 0;
	run->nr_entries = i;
	run->bytes = i * stack_depot_frame_run_entry_bytes(run->mode);

	return 0;
}

int __stack_depot_frame_run_init(const unsigned long *entries,
				 unsigned int nr_entries,
				 struct stack_depot_frame_run *run)
{
	return frame_run_init_lows(entries, nr_entries, run, NULL, 0);
}

static int
stack_depot_frame_run_write_compressed(const struct stack_depot_frame_run *run,
				       const unsigned long *entries, void *dst,
				       u32 *scratch, unsigned int nr_scratch)
{
	unsigned int i;

	if (!scratch || nr_scratch < run->nr_entries)
		return -EINVAL;
	if (stack_depot_ranges_overlap(dst, run->bytes, scratch, run->bytes))
		return -EINVAL;
	if (stack_depot_ranges_overlap(scratch, run->bytes, entries,
				       run->nr_entries * sizeof(*entries)))
		return -EINVAL;

	for (i = 0; i < run->nr_entries; i++) {
		u8 prefix_id;

		if (!frame_try_compress(entries[i], &prefix_id, &scratch[i]))
			return -EINVAL;
		if (prefix_id != run->prefix_id)
			return -EINVAL;
	}

	memcpy(dst, scratch, run->bytes);
	return 0;
}

static int frame_run_write(const struct stack_depot_frame_run *run,
			   const unsigned long *entries, void *dst, size_t dst_size,
			   u32 *scratch, unsigned int nr_scratch)
{
	int ret;

	if (!entries || !dst)
		return -EINVAL;

	ret = stack_depot_frame_run_validate(run);
	if (ret)
		return ret;
	if (dst_size < run->bytes)
		return -EINVAL;
	if (stack_depot_ranges_overlap(dst, run->bytes, entries,
				       run->nr_entries * sizeof(*entries)))
		return -EINVAL;

	if (run->mode == STACK_DEPOT_FRAME_RAW) {
		memcpy(dst, entries, run->bytes);
		return 0;
	}

	return stack_depot_frame_run_write_compressed(run, entries, dst, scratch,
						       nr_scratch);
}

int __stack_depot_frame_run_write(const struct stack_depot_frame_run *run,
				  const unsigned long *entries, void *dst,
				  size_t dst_size, u32 *scratch,
				  unsigned int nr_scratch)
{
	return frame_run_write(run, entries, dst, dst_size, scratch, nr_scratch);
}

static int
stack_depot_frame_run_read_compressed(const struct stack_depot_frame_run *run,
				      const void *src, unsigned long *entries,
				      unsigned long *scratch,
				      unsigned int nr_scratch)
{
	unsigned int i;

	if (!scratch || nr_scratch < run->nr_entries)
		return -EINVAL;

	/* Stage lows first so a bad compressed run cannot leave a partial write. */
	for (i = 0; i < run->nr_entries; i++) {
		u32 low;

		memcpy(&low, (const char *)src + i * sizeof(low), sizeof(low));
		if (!frame_decompress(run->prefix_id, low, &scratch[i]))
			return -EINVAL;
	}

	if (entries != scratch)
		memcpy(entries, scratch, run->nr_entries * sizeof(*entries));
	return 0;
}

static int frame_run_validate_payload(const struct stack_depot_frame_run *run,
				      const void *src)
{
	unsigned long frame;
	unsigned int i;

	if (!src || stack_depot_frame_run_validate(run))
		return -EINVAL;
	if (run->mode == STACK_DEPOT_FRAME_RAW)
		return 0;

	for (i = 0; i < run->nr_entries; i++) {
		u32 low;

		memcpy(&low, (const char *)src + i * sizeof(low), sizeof(low));
		if (!frame_decompress(run->prefix_id, low, &frame))
			return -EINVAL;
	}

	return 0;
}

static bool stack_depot_ranges_overlap(const void *a, size_t a_size,
				       const void *b, size_t b_size)
{
	unsigned long a_start = (unsigned long)a;
	unsigned long b_start = (unsigned long)b;
	unsigned long a_end;
	unsigned long b_end;

	if (!a_size || !b_size)
		return false;
	if (check_add_overflow(a_start, a_size, &a_end) ||
	    check_add_overflow(b_start, b_size, &b_end))
		return true;

	return a_start < b_end && b_start < a_end;
}

static int frame_run_read(const struct stack_depot_frame_run *run,
			  const void *src, size_t src_size,
			  unsigned long *entries, unsigned int max_entries,
			  unsigned long *scratch, unsigned int nr_scratch)
{
	int ret;

	if (!src || !entries)
		return -EINVAL;

	ret = stack_depot_frame_run_validate(run);
	if (ret)
		return ret;
	if (src_size < run->bytes || max_entries < run->nr_entries)
		return -EINVAL;
	if (stack_depot_ranges_overlap(entries,
				       run->nr_entries * sizeof(*entries), src,
				       run->bytes))
		return -EINVAL;

	if (run->mode == STACK_DEPOT_FRAME_RAW) {
		memcpy(entries, src, run->bytes);
		return 0;
	}
	if (!scratch || nr_scratch < run->nr_entries)
		return -EINVAL;
	if (stack_depot_ranges_overlap(entries,
				       run->nr_entries * sizeof(*entries), scratch,
				       run->nr_entries * sizeof(*scratch)))
		return -EINVAL;
	if (stack_depot_ranges_overlap(src, run->bytes, scratch,
				       run->nr_entries * sizeof(*scratch)))
		return -EINVAL;

	return stack_depot_frame_run_read_compressed(run, src, entries, scratch,
					      nr_scratch);
}

int __stack_depot_frame_run_read(const struct stack_depot_frame_run *run,
				 const void *src, size_t src_size,
				 unsigned long *entries, unsigned int max_entries,
				 unsigned long *scratch,
				 unsigned int nr_scratch)
{
	return frame_run_read(run, src, src_size, entries, max_entries, scratch,
			      nr_scratch);
}

size_t __stack_depot_trie_node_size(const struct stack_depot_frame_run *run)
{
	size_t size;

	if (stack_depot_frame_run_validate(run))
		return 0;
	size = offsetof(struct stack_depot_trie_node, data);
	if (check_add_overflow(size, run->bytes, &size))
		return 0;

	return ALIGN(size, sizeof(unsigned long));
}

static int stack_depot_frame_run_slice(const struct stack_depot_frame_run *src,
				       unsigned int start, unsigned int nr_entries,
				       struct stack_depot_frame_run *run)
{
	if (stack_depot_frame_run_validate(src) || !nr_entries || !run)
		return -EINVAL;
	if (start >= src->nr_entries || nr_entries > src->nr_entries - start)
		return -EINVAL;

	*run = *src;
	run->nr_entries = nr_entries;
	run->bytes = nr_entries * stack_depot_frame_run_entry_bytes(run->mode);
	return 0;
}

static int
stack_depot_trie_node_frame(const struct stack_depot_trie_node *node,
			    unsigned int index, unsigned long *frame)
{
	u32 low;

	if (!node || !frame || stack_depot_frame_run_validate(&node->run) ||
	    index >= node->run.nr_entries)
		return -EINVAL;

	if (node->run.mode == STACK_DEPOT_FRAME_RAW) {
		memcpy(frame, node->data + index * sizeof(*frame),
		       sizeof(*frame));
		return 0;
	}

	memcpy(&low, node->data + index * sizeof(low), sizeof(low));
	if (!frame_decompress(node->run.prefix_id, low, frame))
		return -EINVAL;

	return 0;
}

static int
stack_depot_trie_node_first_frame(const struct stack_depot_trie_node *node,
				  unsigned long *frame)
{
	return stack_depot_trie_node_frame(node, 0, frame);
}

int __stack_depot_trie_node_init(void *storage, size_t storage_size,
				 const void *parent, u32 leaf_id,
				 const unsigned long *entries,
				 unsigned int nr_entries, u32 *scratch,
				 unsigned int nr_scratch)
{
	const struct stack_depot_trie_node *parent_node = parent;
	struct stack_depot_trie_node *node = storage;
	struct stack_depot_frame_run run;
	u32 stack_len;
	int ret;

	if (!node || !entries)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)node, __alignof__(*node)))
		return -EINVAL;

	ret = frame_run_init_lows(entries, nr_entries, &run, scratch, nr_scratch);
	if (ret)
		return ret;
	if (run.nr_entries != nr_entries)
		return -EINVAL;
	if (storage_size < __stack_depot_trie_node_size(&run))
		return -EINVAL;
	/* frame_run_init_lows() permits NULL scratch for raw runs only. */
	if (run.mode == STACK_DEPOT_FRAME_COMPRESSED &&
	    (!scratch || nr_scratch < run.nr_entries))
		return -EINVAL;
	if (parent_node) {
		if (!parent_node->stack_len ||
		    parent_node->stack_len > U32_MAX - run.nr_entries ||
		    parent_node->stack_len >
		    CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;
		stack_len = parent_node->stack_len + run.nr_entries;
	} else {
		stack_len = run.nr_entries;
	}

	/* Caller-owned storage is not publishable unless the payload write succeeds. */
	if (run.mode == STACK_DEPOT_FRAME_COMPRESSED)
		/* Copy low-bit payloads staged by frame_run_init_lows(). */
		memcpy(node->data, scratch, run.bytes);
	else
		memcpy(node->data, entries, run.bytes);

	node->parent = parent_node;
	node->children = NULL;
	node->leaf_id = leaf_id;
	node->stack_len = stack_len;
	node->run = run;
	return 0;
}

int __stack_depot_trie_node_init_slice(void *storage, size_t storage_size,
				       const void *parent, u32 leaf_id,
				       const void *src_node, unsigned int start,
				       unsigned int nr_entries)
{
	const struct stack_depot_trie_node *parent_node = parent;
	const struct stack_depot_trie_node *src = src_node;
	struct stack_depot_trie_node *node = storage;
	struct stack_depot_frame_run run;
	size_t entry_bytes;
	size_t src_size;
	u32 stack_len;
	int ret;

	if (!node || !src || !src->stack_len)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)node, __alignof__(*node)))
		return -EINVAL;

	ret = stack_depot_frame_run_slice(&src->run, start, nr_entries, &run);
	if (ret)
		return ret;
	if (storage_size < __stack_depot_trie_node_size(&run))
		return -EINVAL;
	src_size = __stack_depot_trie_node_size(&src->run);
	if (!src_size || stack_depot_ranges_overlap(node, storage_size, src, src_size))
		return -EINVAL;
	if (parent_node) {
		if (!parent_node->stack_len ||
		    parent_node->stack_len > U32_MAX - run.nr_entries ||
		    parent_node->stack_len >
		    CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;
		stack_len = parent_node->stack_len + run.nr_entries;
	} else {
		stack_len = run.nr_entries;
	}

	entry_bytes = stack_depot_frame_run_entry_bytes(src->run.mode);
	memcpy(node->data, src->data + start * entry_bytes, run.bytes);
	node->parent = parent_node;
	node->children = NULL;
	node->leaf_id = leaf_id;
	node->stack_len = stack_len;
	node->run = run;
	return 0;
}

unsigned int __stack_depot_trie_node_match(const void *node_ptr,
					   const unsigned long *entries,
					   unsigned int nr_entries)
{
	const struct stack_depot_trie_node *node = node_ptr;
	unsigned int limit;
	unsigned int i;

	if (!node || !entries || !nr_entries ||
	    stack_depot_frame_run_validate(&node->run))
		return 0;

	limit = min(node->run.nr_entries, nr_entries);
	if (node->run.mode == STACK_DEPOT_FRAME_RAW) {
		for (i = 0; i < limit; i++) {
			unsigned long frame;

			memcpy(&frame, node->data + i * sizeof(frame), sizeof(frame));
			if (frame != entries[i])
				break;
		}

		return i;
	}

	for (i = 0; i < limit; i++) {
		unsigned long frame;

		if (stack_depot_trie_node_frame(node, i, &frame))
			return 0;
		if (frame != entries[i])
			break;
	}

	return i;
}

static bool trie_ancestor_overlaps(const struct stack_depot_trie_node *node,
				   const void *ptr, size_t size)
{
	unsigned int depth = 0;

	for (; node; node = node->parent, depth++) {
		size_t child_size;
		size_t node_size;

		if (depth >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return true;
		if (stack_depot_frame_run_validate(&node->run))
			return true;

		node_size = __stack_depot_trie_node_size(&node->run);
		if (!node_size)
			return true;
		if (stack_depot_ranges_overlap(ptr, size, node, node_size))
			return true;

		if (!node->children)
			continue;
		child_size = trie_child_array_size_for_capacity(node->children->capacity);
		if (!child_size)
			return true;
		if (stack_depot_ranges_overlap(ptr, size, node->children,
					       child_size))
			return true;
	}

	return false;
}

static bool trie_chain_overlaps(const struct stack_depot_trie_node *node,
				const void *ptr, size_t size)
{
	unsigned int depth = 0;

	for (; node; depth++) {
		const struct stack_depot_trie_child_array *children;
		size_t child_size;
		size_t node_size;

		if (depth >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return true;
		if (stack_depot_frame_run_validate(&node->run))
			return true;

		node_size = __stack_depot_trie_node_size(&node->run);
		if (!node_size)
			return true;
		if (stack_depot_ranges_overlap(ptr, size, node, node_size))
			return true;

		children = node->children;
		if (!children)
			break;
		if (children->nr_children != 1)
			return true;
		child_size = trie_child_array_size_for_capacity(children->capacity);
		if (!child_size)
			return true;
		if (stack_depot_ranges_overlap(ptr, size, children, child_size))
			return true;
		if (!children->children[0])
			return true;
		if (children->children[0]->parent != node)
			return true;
		node = children->children[0];
	}

	return false;
}

static bool
trie_child_array_subtree_overlaps(const struct stack_depot_trie_child_array *array,
				  const struct stack_depot_trie_node *parent,
				  const void *ptr, size_t size)
{
	const struct stack_depot_trie_node *node;
	size_t array_size;
	unsigned int depth = 0;

	if (!array)
		return false;
	array_size = trie_child_array_size_for_capacity(array->capacity);
	if (!array_size)
		return true;
	if (stack_depot_ranges_overlap(ptr, size, array, array_size))
		return true;
	if (!array->nr_children)
		return false;

	node = array->children[0];
	if (!node || node->parent != parent)
		return true;

	for (;;) {
		const struct stack_depot_trie_child_array *children;
		const struct stack_depot_trie_child_array *siblings;
		const struct stack_depot_trie_node *child;
		const struct stack_depot_trie_node *node_parent;
		size_t child_size;
		size_t node_size;
		unsigned int i;

		if (depth >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return true;
		if (stack_depot_frame_run_validate(&node->run))
			return true;

		node_size = __stack_depot_trie_node_size(&node->run);
		if (!node_size)
			return true;
		if (stack_depot_ranges_overlap(ptr, size, node, node_size))
			return true;

		children = node->children;
		if (children) {
			child_size = trie_child_array_size_for_capacity(children->capacity);
			if (!child_size)
				return true;
			if (stack_depot_ranges_overlap(ptr, size, children,
						       child_size))
				return true;
			if (children->nr_children) {
				child = children->children[0];
				if (!child || child->parent != node)
					return true;
				node = child;
				depth++;
				continue;
			}
		}

		for (;;) {
			node_parent = node->parent;
			if (node_parent == parent) {
				siblings = array;
			} else {
				if (!node_parent || !node_parent->children)
					return true;
				siblings = node_parent->children;
			}

			for (i = 0; i < siblings->nr_children; i++) {
				if (siblings->children[i] == node)
					break;
			}
			if (i == siblings->nr_children)
				return true;
			if (i + 1 < siblings->nr_children) {
				node = siblings->children[i + 1];
				if (!node || node->parent != node_parent)
					return true;
				break;
			}
			if (node_parent == parent)
				return false;
			if (!depth)
				return true;
			node = node_parent;
			depth--;
		}
	}
}

static const struct stack_depot_trie_node *
trie_load_parent(const struct stack_depot_trie_node *node)
{
	/* Pairs with trie_publish_parent(). */
	return smp_load_acquire(&node->parent);
}

static void
trie_publish_parent(struct stack_depot_trie_node *child,
		    const struct stack_depot_trie_node *parent)
{
	/* Pairs with trie_load_parent(). */
	smp_store_release(&child->parent, parent);
}

static bool
trie_node_slots_subtree_overlap(const struct stack_depot_trie_child_array *array,
				const struct stack_depot_trie_node *parent,
				const struct stack_depot_trie_node_slot *slots,
				unsigned int nr_slots)
{
	unsigned int i;

	for (i = 0; i < nr_slots; i++) {
		if (trie_child_array_subtree_overlaps(array, parent, slots[i].node, slots[i].size))
			return true;
	}

	return false;
}

static bool
trie_child_slots_subtree_overlap(const struct stack_depot_trie_child_array *array,
				 const struct stack_depot_trie_node *parent,
				 const struct stack_depot_trie_child_array_slot *slots,
				 unsigned int nr_slots)
{
	unsigned int i;

	for (i = 0; i < nr_slots; i++) {
		if (trie_child_array_subtree_overlaps(array, parent, slots[i].array, slots[i].size))
			return true;
	}

	return false;
}

static bool
trie_node_slot_overlaps(const struct stack_depot_trie_node_slot *slots,
			unsigned int used, const void *ptr, size_t size)
{
	unsigned int i;

	for (i = 0; i < used; i++) {
		if (stack_depot_ranges_overlap(ptr, size, slots[i].node,
					       slots[i].size))
			return true;
	}

	return false;
}

static bool
trie_child_slot_overlaps(const struct stack_depot_trie_child_array_slot *slots,
			 unsigned int used, const void *ptr, size_t size)
{
	unsigned int i;

	for (i = 0; i < used; i++) {
		if (stack_depot_ranges_overlap(ptr, size, slots[i].array,
					       slots[i].size))
			return true;
	}

	return false;
}

static const struct stack_depot_trie_child_array **
trie_publish_slot(struct stack_depot_trie_root *root,
		  struct stack_depot_trie_node *parent)
{
	if ((root && parent) || (!root && !parent))
		return NULL;
	if (root)
		return &root->children;
	return &parent->children;
}

static bool
trie_child_array_can_append(const struct stack_depot_trie_child_array *array,
			    unsigned int pos)
{
	return array && pos == array->nr_children && array->nr_children < array->capacity;
}

static int trie_insert_append_precheck(struct stack_depot_trie_root *root,
				       struct stack_depot_trie_node *parent,
				       const unsigned long *entries,
				       unsigned int nr_entries,
				       const struct stack_depot_trie_node_slot *node_slots,
				       unsigned int nr_node_slots,
				       const struct stack_depot_trie_child_array_slot *child_slots,
				       unsigned int nr_child_slots, void *new_storage,
				       size_t new_storage_size)
{
	const struct stack_depot_trie_child_array **slot;
	const struct stack_depot_trie_child_array *children;
	size_t size;
	unsigned int pos;
	bool found;

	if (!entries || !nr_entries)
		return -EINVAL;
	if (!entries[0])
		return -EINVAL;
	if ((nr_node_slots && !node_slots) || (nr_child_slots && !child_slots))
		return -EINVAL;
	if (new_storage &&
	    !IS_ALIGNED((unsigned long)new_storage,
			 __alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;

	slot = trie_publish_slot(root, parent);
	if (!slot)
		return -EINVAL;
	if (new_storage &&
	    stack_depot_ranges_overlap(new_storage, new_storage_size,
				       slot, sizeof(*slot)))
		return -EINVAL;
	if (root) {
		if (trie_node_slot_overlaps(node_slots, nr_node_slots, slot,
					    sizeof(*slot)))
			return -EINVAL;
		if (trie_child_slot_overlaps(child_slots, nr_child_slots, slot,
					     sizeof(*slot)))
			return -EINVAL;
	}
	if (new_storage && parent &&
	    trie_ancestor_overlaps(parent, new_storage, new_storage_size))
		return -EINVAL;
	if (new_storage &&
	    (trie_node_slot_overlaps(node_slots, nr_node_slots, new_storage,
				     new_storage_size) ||
	     trie_child_slot_overlaps(child_slots, nr_child_slots, new_storage,
				      new_storage_size)))
		return -EINVAL;

	/* Pairs with append publication's smp_store_release(). */
	children = smp_load_acquire(slot);
	if (!new_storage) {
		if (!children)
			return -EINVAL;
		if (stack_depot_trie_child_lower_bound(children, entries[0], &pos,
						       &found))
			return -EINVAL;
		if (found || !trie_child_array_can_append(children, pos))
			return -EINVAL;
		return 0;
	}
	size = __stack_depot_trie_child_array_size(children ?
					       children->nr_children + 1 : 1);
	if (!size || new_storage_size < size)
		return -EINVAL;
	if (children) {
		size = trie_child_array_size_for_capacity(children->capacity);
		if (!size)
			return -EINVAL;
		if (stack_depot_ranges_overlap(children, size, new_storage,
					       new_storage_size))
			return -EINVAL;
		if (trie_node_slot_overlaps(node_slots, nr_node_slots, children,
					    size) ||
		    trie_child_slot_overlaps(child_slots, nr_child_slots, children,
					     size))
			return -EINVAL;
		if (stack_depot_trie_child_lower_bound(children, entries[0], &pos,
						       &found))
			return -EINVAL;
		if (found)
			return -EINVAL;
	}

	return 0;
}

static int trie_insert_descend_precheck(struct stack_depot_trie_root *root,
					struct stack_depot_trie_node *parent,
					const struct stack_depot_trie_node_slot *node_slots,
					unsigned int nr_node_slots,
					const struct stack_depot_trie_child_array_slot *child_slots,
					unsigned int nr_child_slots,
					void *new_storage, size_t new_storage_size)
{
	const struct stack_depot_trie_child_array **slot;
	const struct stack_depot_trie_child_array *children;
	bool overlap;
	size_t size;

	slot = trie_publish_slot(root, parent);
	if (!slot)
		return -EINVAL;
	if ((nr_node_slots && !node_slots) || (nr_child_slots && !child_slots))
		return -EINVAL;
	if (new_storage &&
	    !IS_ALIGNED((unsigned long)new_storage,
			 __alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;
	if (new_storage &&
	    stack_depot_ranges_overlap(new_storage, new_storage_size,
				       slot, sizeof(*slot)))
		return -EINVAL;
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, slot,
				    sizeof(*slot)))
		return -EINVAL;
	if (trie_child_slot_overlaps(child_slots, nr_child_slots, slot,
				     sizeof(*slot)))
		return -EINVAL;

	/* Pairs with append publication's smp_store_release(). */
	children = smp_load_acquire(slot);
	if (!children)
		return -EINVAL;
	size = trie_child_array_size_for_capacity(children->capacity);
	if (!size)
		return -EINVAL;
	if (new_storage &&
	    stack_depot_ranges_overlap(children, size, new_storage,
				       new_storage_size))
		return -EINVAL;
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, children, size))
		return -EINVAL;
	if (trie_child_slot_overlaps(child_slots, nr_child_slots, children,
				     size))
		return -EINVAL;

	if (trie_node_slots_subtree_overlap(children, parent, node_slots, nr_node_slots))
		return -EINVAL;
	if (trie_child_slots_subtree_overlap(children, parent, child_slots, nr_child_slots))
		return -EINVAL;
	overlap = new_storage &&
		trie_child_array_subtree_overlaps(children, parent, new_storage,
						  new_storage_size);
	if (overlap)
		return -EINVAL;

	return 0;
}

static int
trie_child_array_replace_precheck(const struct stack_depot_trie_child_array *old_array,
				  const struct stack_depot_trie_node *old_child,
				  void *new_storage, size_t new_storage_size,
				  unsigned int *pos)
{
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned long frame;
	bool found;
	size_t size;

	if (!old_array || !old_child || !new_array || !pos)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_array,
			__alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;
	if (old_array == new_array)
		return -EINVAL;

	size = trie_child_array_size_for_capacity(old_array->capacity);
	if (!size || new_storage_size < size)
		return -EINVAL;
	if (stack_depot_ranges_overlap(old_array, size, new_array, new_storage_size))
		return -EINVAL;
	if (stack_depot_trie_node_first_frame(old_child, &frame))
		return -EINVAL;
	if (stack_depot_trie_child_lower_bound(old_array, frame, pos, &found) ||
	    !found || old_array->children[*pos] != old_child)
		return -EINVAL;

	return 0;
}

static void
trie_child_array_replace_at(const struct stack_depot_trie_child_array *old_array,
			    const struct stack_depot_trie_node *new_child,
			    void *new_storage, size_t new_storage_size,
			    unsigned int pos)
{
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned int i;

	new_array->nr_children = old_array->nr_children;
	new_array->capacity = trie_child_array_storage_capacity(new_storage_size);
	for (i = 0; i < old_array->nr_children; i++)
		new_array->children[i] = old_array->children[i];
	new_array->children[pos] = new_child;
}

static int
trie_clone_promoted_node(const struct stack_depot_trie_node *old_node,
			 u32 leaf_id,
			 const struct stack_depot_trie_node_slot *slot)
{
	struct stack_depot_trie_node *new_node;
	size_t size;

	if (!old_node || !leaf_id || !slot || !slot->node)
		return -EINVAL;
	if (old_node->leaf_id || !old_node->stack_len)
		return -EINVAL;
	if (stack_depot_frame_run_validate(&old_node->run))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)slot->node,
			__alignof__(struct stack_depot_trie_node)))
		return -EINVAL;

	size = __stack_depot_trie_node_size(&old_node->run);
	if (!size || slot->size < size)
		return -EINVAL;
	if (stack_depot_ranges_overlap(slot->node, slot->size, old_node, size))
		return -EINVAL;

	new_node = slot->node;
	memcpy(new_node, old_node, size);
	new_node->leaf_id = leaf_id;
	return 0;
}

static void trie_reparent_children(struct stack_depot_trie_node *parent)
{
	const struct stack_depot_trie_child_array *children = parent->children;
	unsigned int i;

	if (!children)
		return;
	for (i = 0; i < children->nr_children; i++) {
		struct stack_depot_trie_node *child;

		/* Child arrays are const for readers; writers serialize reparenting. */
		child = (struct stack_depot_trie_node *)children->children[i];
		trie_publish_parent(child, parent);
	}
}

static int
trie_promote_precheck(struct stack_depot_trie_root *root,
		      struct stack_depot_trie_node *parent,
		      const struct stack_depot_trie_node *child,
		      const struct stack_depot_trie_node_slot *slot,
		      void *new_storage, size_t new_storage_size,
		      const struct stack_depot_trie_child_array **old_array,
		      unsigned int *pos)
{
	const struct stack_depot_trie_child_array **publish_slot;
	const struct stack_depot_trie_child_array *array;
	const struct stack_depot_trie_node *new_child;
	size_t new_child_size;

	if (!child || !slot || !slot->node || !new_storage || !old_array || !pos)
		return -EINVAL;
	if (child->parent != parent || child->leaf_id)
		return -EINVAL;

	publish_slot = trie_publish_slot(root, parent);
	if (!publish_slot)
		return -EINVAL;
	if (stack_depot_ranges_overlap(slot->node, slot->size, publish_slot,
				       sizeof(*publish_slot)))
		return -EINVAL;
	if (stack_depot_ranges_overlap(new_storage, new_storage_size, publish_slot,
				       sizeof(*publish_slot)))
		return -EINVAL;
	if (parent && (trie_ancestor_overlaps(parent, slot->node, slot->size) ||
		       trie_ancestor_overlaps(parent, new_storage, new_storage_size)))
		return -EINVAL;
	if (stack_depot_ranges_overlap(slot->node, slot->size, new_storage,
				       new_storage_size))
		return -EINVAL;

	/* Pairs with append and promote publication's smp_store_release(). */
	*old_array = smp_load_acquire(publish_slot);
	if (!*old_array)
		return -EINVAL;
	array = *old_array;
	new_child = slot->node;
	new_child_size = __stack_depot_trie_node_size(&child->run);
	if (!new_child_size || slot->size < new_child_size)
		return -EINVAL;
	if (trie_child_array_subtree_overlaps(array, parent, new_child, new_child_size))
		return -EINVAL;
	if (trie_child_array_subtree_overlaps(array, parent, new_storage, new_storage_size))
		return -EINVAL;

	return trie_child_array_replace_precheck(array, child, new_storage,
						new_storage_size, pos);
}

static int
trie_promote_child(struct stack_depot_trie_root *root,
		   struct stack_depot_trie_node *parent,
		   const struct stack_depot_trie_node *child, u32 leaf_id,
		   const struct stack_depot_trie_node_slot *slot,
		   void *new_storage, size_t new_storage_size,
		   const struct stack_depot_trie_publish_prepare *prepare)
{
	const struct stack_depot_trie_child_array **publish_slot;
	const struct stack_depot_trie_child_array *old_array;
	struct stack_depot_trie_leaf_update update;
	size_t child_size;
	unsigned int pos;
	int ret;

	if (!leaf_id)
		return -EINVAL;
	ret = trie_promote_precheck(root, parent, child, slot, new_storage,
				    new_storage_size, &old_array, &pos);
	if (ret)
		return ret;
	ret = trie_clone_promoted_node(child, leaf_id, slot);
	if (ret)
		return ret;
	child_size = __stack_depot_trie_node_size(&child->run);
	if (!child_size)
		return -EINVAL;
	if (prepare) {
		if (!prepare->fn)
			return -EINVAL;
		update.leaf_id = leaf_id;
		update.leaf = slot->node;
		ret = prepare->fn(&update, 1, prepare->ctx);
		if (ret)
			return ret;
	}
	trie_child_array_replace_at(old_array, slot->node, new_storage,
				    new_storage_size, pos);
	trie_reparent_children(slot->node);

	publish_slot = trie_publish_slot(root, parent);
	/* Publish the fully initialized replacement array last. */
	smp_store_release(publish_slot, new_storage);
	if (prepare && prepare->retire_locked)
		trie_retire_object_node_locked(old_array, child, child_size);
	else
		trie_retire_object_node(old_array, child, child_size);
	return 0;
}

static int trie_append_chain_validate(const struct stack_depot_trie_node *parent,
				      const unsigned long *entries,
				      unsigned int nr_entries,
				      const struct stack_depot_trie_node_slot *node_slots,
				      unsigned int nr_node_slots,
				      const struct stack_depot_trie_child_array_slot *child_slots,
				      unsigned int nr_child_slots, u32 *scratch,
				      unsigned int nr_scratch, unsigned int *nr_runs)
{
	unsigned int child_slots_needed;
	unsigned int pos = 0;
	unsigned int used = 0;
	u32 stack_len = parent ? parent->stack_len : 0;

	if (!entries || !nr_entries || !node_slots || !nr_runs)
		return -EINVAL;
	if (parent && !parent->stack_len)
		return -EINVAL;

	while (pos < nr_entries) {
		const struct stack_depot_trie_node_slot *slot;
		struct stack_depot_frame_run run;
		size_t size;

		if (__stack_depot_frame_run_init(&entries[pos], nr_entries - pos,
						 &run))
			return -EINVAL;
		if (used >= nr_node_slots)
			return -EINVAL;
		slot = &node_slots[used];
		if (!slot->node)
			return -EINVAL;
		if (run.mode == STACK_DEPOT_FRAME_COMPRESSED &&
		    (!scratch || nr_scratch < run.nr_entries))
			return -EINVAL;
		if (stack_len > U32_MAX - run.nr_entries ||
		    stack_len > CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;

		size = __stack_depot_trie_node_size(&run);
		if (slot->size < size)
			return -EINVAL;
		if (!IS_ALIGNED((unsigned long)slot->node,
				__alignof__(struct stack_depot_trie_node)))
			return -EINVAL;
		if (trie_ancestor_overlaps(parent, slot->node, slot->size))
			return -EINVAL;
		if (trie_node_slot_overlaps(node_slots, used, slot->node, slot->size))
			return -EINVAL;

		stack_len += run.nr_entries;
		pos += run.nr_entries;
		used++;
	}

	child_slots_needed = used > 1 ? used - 1 : 0;
	if (child_slots_needed) {
		unsigned int i;

		if (!child_slots || nr_child_slots < child_slots_needed)
			return -EINVAL;
		for (i = 0; i < child_slots_needed; i++) {
			unsigned long addr = (unsigned long)child_slots[i].array;

			if (!child_slots[i].array || child_slots[i].size <
			    __stack_depot_trie_child_array_size(1))
				return -EINVAL;
			if (!IS_ALIGNED(addr,
					__alignof__(struct stack_depot_trie_child_array)))
				return -EINVAL;
			if (trie_ancestor_overlaps(parent, child_slots[i].array,
						   child_slots[i].size))
				return -EINVAL;
			if (trie_node_slot_overlaps(node_slots, used,
						    child_slots[i].array,
						    child_slots[i].size))
				return -EINVAL;
			if (trie_child_slot_overlaps(child_slots, i,
						     child_slots[i].array,
						     child_slots[i].size))
				return -EINVAL;
		}
	}

	*nr_runs = used;
	return 0;
}

int
__stack_depot_trie_append_chain(const void *parent_ptr, u32 leaf_id,
				const unsigned long *entries,
				unsigned int nr_entries,
				const struct stack_depot_trie_node_slot *node_slots,
				unsigned int nr_node_slots,
				const struct stack_depot_trie_child_array_slot *child_slots,
				unsigned int nr_child_slots, u32 *scratch,
				unsigned int nr_scratch, const void **head,
				const void **tail, unsigned int *nr_used)
{
	const struct stack_depot_trie_node *parent = parent_ptr;
	const struct stack_depot_trie_node *prev = parent;
	unsigned int pos = 0;
	unsigned int used;
	unsigned int i;

	if (!leaf_id || !head || !tail || !nr_used)
		return -EINVAL;
	if (trie_append_chain_validate(parent, entries, nr_entries, node_slots,
				       nr_node_slots, child_slots, nr_child_slots,
				       scratch, nr_scratch, &used))
		return -EINVAL;

	for (i = 0; i < used; i++) {
		struct stack_depot_frame_run run;
		struct stack_depot_trie_node *node = node_slots[i].node;
		u32 id;

		if (__stack_depot_frame_run_init(&entries[pos], nr_entries - pos,
						 &run))
			return -EINVAL;
		id = pos + run.nr_entries == nr_entries ? leaf_id : 0;
		if (__stack_depot_trie_node_init(node, node_slots[i].size, prev,
						 id, &entries[pos], run.nr_entries,
						 scratch, nr_scratch))
			return -EINVAL;

		prev = node;
		pos += run.nr_entries;
	}

	for (i = 0; i + 1 < used; i++) {
		const void *next = node_slots[i + 1].node;
		struct stack_depot_trie_node *node = node_slots[i].node;
		void *array = child_slots[i].array;
		size_t size = child_slots[i].size;

		if (__stack_depot_trie_child_array_insert(NULL, next, array, size))
			return -EINVAL;
		node->children = array;
	}

	*head = node_slots[0].node;
	*tail = node_slots[used - 1].node;
	*nr_used = used;
	return 0;
}

static int trie_publish_append_prepare(struct stack_depot_trie_root *root,
				       void *parent_ptr, const void *head_ptr,
				       void *new_storage, size_t new_storage_size,
				       const struct stack_depot_trie_publish_prepare *prepare,
				       u32 leaf_id,
				       const void *leaf)
{
	const struct stack_depot_trie_child_array *old_array;
	const struct stack_depot_trie_node *head = head_ptr;
	const struct stack_depot_trie_child_array **slot;
	struct stack_depot_trie_child_array *append_array = NULL;
	struct stack_depot_trie_node *parent = parent_ptr;
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned int append_pos = 0;
	size_t storage_size = new_storage_size;
	size_t new_size;
	size_t old_size;
	int ret;

	if ((root && parent) || (!root && !parent) || !head)
		return -EINVAL;
	if (head->parent != parent)
		return -EINVAL;

	if (root) {
		if (new_array &&
		    stack_depot_ranges_overlap(new_array, storage_size,
					       &root->children,
					       sizeof(root->children)))
			return -EINVAL;
		slot = &root->children;
	} else {
		if (new_array &&
		    trie_ancestor_overlaps(parent, new_array, storage_size))
			return -EINVAL;
		slot = &parent->children;
	}

	/* Pairs with append publication's smp_store_release(). */
	old_array = smp_load_acquire(slot);
	old_size = old_array ?
		trie_child_array_size_for_capacity(old_array->capacity) : 0;
	new_size = old_array ? old_array->nr_children + 1 : 1;
	new_size = __stack_depot_trie_child_array_size(new_size);
	if (!new_size)
		return -EINVAL;
	if (!new_array) {
		unsigned long frame;
		unsigned int pos;
		bool found;

		if (!old_array)
			return -EINVAL;
		if (stack_depot_trie_node_first_frame(head, &frame))
			return -EINVAL;
		if (stack_depot_trie_child_lower_bound(old_array, frame, &pos, &found))
			return -EINVAL;
		if (found || !trie_child_array_can_append(old_array, pos))
			return -EINVAL;
		append_array = (struct stack_depot_trie_child_array *)old_array;
		append_pos = pos;
	}
	if (new_array && storage_size < new_size)
		return -EINVAL;
	if (new_array && old_array &&
	    stack_depot_ranges_overlap(old_array, old_size, new_array,
				       storage_size))
		return -EINVAL;
	if (new_array && trie_chain_overlaps(head, new_array, storage_size))
		return -EINVAL;
	if (new_array &&
	    __stack_depot_trie_child_array_insert(old_array, head, new_array, storage_size))
		return -EINVAL;
	if (prepare) {
		struct stack_depot_trie_leaf_update update = {
			.leaf_id = leaf_id,
			.leaf = leaf,
		};

		if (!prepare->fn)
			return -EINVAL;
		if (!leaf_id || !leaf)
			return -EINVAL;
		ret = prepare->fn(&update, 1, prepare->ctx);
		if (ret)
			return ret;
	}
	if (!new_array) {
		append_array->children[append_pos] = head;
		/* Pairs with child lookup's smp_load_acquire(). */
		smp_store_release(&append_array->nr_children, append_pos + 1);
		return 0;
	}

	/* Publish the fully initialized replacement array last. */
	smp_store_release(slot, new_array);
	if (prepare && prepare->retire_locked)
		trie_retire_object_node_locked(old_array, NULL, 0);
	else
		trie_retire_object(old_array);
	return 0;
}

int
__stack_depot_trie_publish_append(struct stack_depot_trie_root *root,
				  void *parent_ptr, const void *head_ptr,
				  void *new_storage, size_t new_storage_size)
{
	return trie_publish_append_prepare(root, parent_ptr, head_ptr, new_storage,
					   new_storage_size, NULL, 0, NULL);
}

int
__stack_depot_trie_lookup_step(const struct stack_depot_trie_root *root,
			       const void *parent_ptr, const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_lookup *lookup)
{
	const struct stack_depot_trie_child_array *children;
	const struct stack_depot_trie_node *parent = parent_ptr;
	const struct stack_depot_trie_node *node;
	struct stack_depot_trie_lookup tmp;
	unsigned int matched;
	unsigned int pos;
	unsigned long key;
	bool found;

	if (!entries || !nr_entries || !lookup)
		return -EINVAL;
	if ((root && parent) || (!root && !parent))
		return -EINVAL;

	if (root) {
		/* Pairs with append publication's smp_store_release(). */
		children = smp_load_acquire(&root->children);
	} else {
		/* Pairs with append publication's smp_store_release(). */
		children = smp_load_acquire(&parent->children);
	}

	tmp.status = STACK_DEPOT_TRIE_LOOKUP_APPEND;
	tmp.parent = parent;
	tmp.node = NULL;
	tmp.matched = 0;
	if (!children) {
		*lookup = tmp;
		return 0;
	}

	key = entries[0];
	if (stack_depot_trie_child_lower_bound(children, key, &pos, &found))
		return -EINVAL;
	if (!found) {
		*lookup = tmp;
		return 0;
	}

	node = children->children[pos];
	if (!node)
		return -EINVAL;
	/*
	 * Do not validate node->parent here. COW splits may reparent descendants
	 * to an equivalent replacement prefix before the structural publish; the
	 * multi-step finder has enough prefix context to validate that equivalence.
	 */

	matched = __stack_depot_trie_node_match(node, entries, nr_entries);
	if (!matched)
		return -EINVAL;

	tmp.node = node;
	tmp.matched = matched;
	if (matched < node->run.nr_entries)
		tmp.status = STACK_DEPOT_TRIE_LOOKUP_SPLIT;
	else if (matched < nr_entries)
		tmp.status = STACK_DEPOT_TRIE_LOOKUP_DESCEND;
	else if (node->leaf_id)
		tmp.status = STACK_DEPOT_TRIE_LOOKUP_FOUND;
	else
		tmp.status = STACK_DEPOT_TRIE_LOOKUP_PROMOTE;

	*lookup = tmp;
	return 0;
}

const void *
__stack_depot_trie_find_leaf(const struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries)
{
	const struct stack_depot_trie_root *lookup_root = root;
	const struct stack_depot_trie_node *parent = NULL;
	unsigned int pos = 0;

	if (!root || !entries || !nr_entries)
		return NULL;

	while (pos < nr_entries) {
		const struct stack_depot_trie_node *node;
		struct stack_depot_trie_lookup lookup;

		if (__stack_depot_trie_lookup_step(lookup_root, parent,
						   &entries[pos], nr_entries - pos,
						   &lookup))
			return NULL;
		node = lookup.node;
		if (node) {
			const struct stack_depot_trie_node *node_parent;

			node_parent = trie_load_parent(node);
			if (node->stack_len != pos + lookup.matched)
				return NULL;
			if (node_parent != parent &&
			    !trie_parent_chain_matches_prefix(node_parent, entries,
							      pos))
				return NULL;
		}

		switch (lookup.status) {
		case STACK_DEPOT_TRIE_LOOKUP_FOUND:
			if (pos + lookup.matched == nr_entries)
				return node;
			return NULL;
		case STACK_DEPOT_TRIE_LOOKUP_DESCEND:
			if (!node || !lookup.matched)
				return NULL;
			pos += lookup.matched;
			parent = node;
			lookup_root = NULL;
			break;
		case STACK_DEPOT_TRIE_LOOKUP_APPEND:
		case STACK_DEPOT_TRIE_LOOKUP_PROMOTE:
		case STACK_DEPOT_TRIE_LOOKUP_SPLIT:
			return NULL;
		}
	}

	return NULL;
}

static int trie_split_child(struct stack_depot_trie_root *root,
			    struct stack_depot_trie_node *parent,
			    const struct stack_depot_trie_node *child,
			    unsigned int matched, u32 leaf_id,
			    const unsigned long *entries,
			    unsigned int nr_entries,
			    const struct stack_depot_trie_node_slot *node_slots,
			    unsigned int nr_node_slots,
			    const struct stack_depot_trie_child_array_slot *child_slots,
			    unsigned int nr_child_slots, u32 *scratch,
			    unsigned int nr_scratch, void *new_storage,
			    size_t new_storage_size,
			    const struct stack_depot_trie_publish_prepare *prepare,
			    const void **tail,
			    unsigned int *nr_used);

int
__stack_depot_trie_insert_append_prepare(struct stack_depot_trie_root *root,
					 void *parent_ptr, u32 leaf_id,
					 const unsigned long *entries,
					 unsigned int nr_entries,
					 const struct stack_depot_trie_node_slot *node_slots,
					 unsigned int nr_node_slots,
					 const struct stack_depot_trie_child_array_slot
					 *child_slots,
					 unsigned int nr_child_slots, u32 *scratch,
					 unsigned int nr_scratch, void *new_storage,
					 size_t new_storage_size,
					 const struct stack_depot_trie_publish_prepare *prepare,
					 const void **tail,
					 unsigned int *nr_used)
{
	const void *head;
	const void *last;
	unsigned int used;
	struct stack_depot_trie_node *parent = parent_ptr;
	struct stack_depot_trie_lookup lookup;
	int ret;

	if (!leaf_id || !tail || !nr_used)
		return -EINVAL;

	for (;;) {
		ret = __stack_depot_trie_lookup_step(root, parent, entries, nr_entries, &lookup);
		if (ret)
			return ret;
		if (lookup.status != STACK_DEPOT_TRIE_LOOKUP_DESCEND)
			break;
		ret = trie_insert_descend_precheck(root, parent, node_slots,
						   nr_node_slots, child_slots,
						   nr_child_slots, new_storage,
						   new_storage_size);
		if (ret)
			return ret;
		/* Insert callers serialize writers and may publish below this node. */
		parent = (struct stack_depot_trie_node *)lookup.node;
		root = NULL;
		entries += lookup.matched;
		nr_entries -= lookup.matched;
	}

	if (!entries || !nr_entries)
		return -EINVAL;
	if (lookup.status == STACK_DEPOT_TRIE_LOOKUP_SPLIT)
		return trie_split_child(root, parent, lookup.node, lookup.matched,
					leaf_id, entries, nr_entries, node_slots,
					nr_node_slots, child_slots, nr_child_slots,
					scratch, nr_scratch, new_storage,
					new_storage_size, prepare, tail,
					nr_used);
	if (lookup.status == STACK_DEPOT_TRIE_LOOKUP_PROMOTE) {
		if (!node_slots || !nr_node_slots)
			return -EINVAL;
		ret = trie_promote_child(root, parent, lookup.node, leaf_id,
					 &node_slots[0], new_storage, new_storage_size,
					 prepare);
		if (ret)
			return ret;
		*tail = node_slots[0].node;
		*nr_used = 1;
		return 0;
	}
	if (lookup.status != STACK_DEPOT_TRIE_LOOKUP_APPEND)
		return -EINVAL;

	ret = trie_insert_append_precheck(root, parent, entries, nr_entries,
					  node_slots, nr_node_slots, child_slots,
					  nr_child_slots, new_storage,
					  new_storage_size);
	if (ret)
		return ret;
	ret = __stack_depot_trie_append_chain(parent, leaf_id, entries, nr_entries,
					      node_slots, nr_node_slots, child_slots,
					      nr_child_slots, scratch, nr_scratch,
					      &head, &last, &used);
	if (ret)
		return ret;
	ret = trie_publish_append_prepare(root, parent, head, new_storage,
					  new_storage_size, prepare, leaf_id, last);
	if (ret)
		return ret;

	*tail = last;
	*nr_used = used;
	return 0;
}

int __stack_depot_trie_insert_append(struct stack_depot_trie_root *root,
				     void *parent, u32 leaf_id,
				     const unsigned long *entries,
				     unsigned int nr_entries,
				     const struct stack_depot_trie_node_slot *node_slots,
				     unsigned int nr_node_slots,
				     const struct stack_depot_trie_child_array_slot *child_slots,
				     unsigned int nr_child_slots, u32 *scratch,
				     unsigned int nr_scratch, void *new_storage,
				     size_t new_storage_size, const void **tail,
				     unsigned int *nr_used)
{
	return __stack_depot_trie_insert_append_prepare(root, parent, leaf_id,
						       entries, nr_entries, node_slots,
						       nr_node_slots, child_slots,
						       nr_child_slots, scratch,
						       nr_scratch, new_storage,
						       new_storage_size, NULL, tail,
						       nr_used);
}

static int trie_plan_append_chain(unsigned int base_stack_len,
				  const unsigned long *entries,
				  unsigned int nr_entries,
				  struct stack_depot_trie_node_slot *node_slots,
				  unsigned int nr_node_slots,
				  struct stack_depot_trie_child_array_slot *child_slots,
				  unsigned int nr_child_slots,
				  unsigned int *nr_used,
				  unsigned int *nr_child_used)
{
	unsigned int pos = 0;
	unsigned int stack_len = base_stack_len;
	unsigned int used = 0;

	if (!entries || !nr_entries || !node_slots || !nr_used || !nr_child_used)
		return -EINVAL;

	while (pos < nr_entries) {
		struct stack_depot_frame_run run;

		if (used >= nr_node_slots)
			return -EINVAL;
		if (__stack_depot_frame_run_init(&entries[pos], nr_entries - pos,
						 &run))
			return -EINVAL;
		if (stack_len > U32_MAX - run.nr_entries ||
		    stack_len > CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;

		node_slots[used].node = NULL;
		node_slots[used].size = __stack_depot_trie_node_size(&run);
		if (!node_slots[used].size)
			return -EINVAL;
		stack_len += run.nr_entries;
		pos += run.nr_entries;
		used++;
	}

	if (used > 1) {
		unsigned int i;

		if (!child_slots || nr_child_slots < used - 1)
			return -EINVAL;
		for (i = 0; i < used - 1; i++) {
			child_slots[i].array = NULL;
			child_slots[i].size = __stack_depot_trie_child_array_size(1);
			if (!child_slots[i].size)
				return -EINVAL;
		}
	}

	*nr_used = used;
	*nr_child_used = used > 1 ? used - 1 : 0;
	return 0;
}

static bool trie_node_depth_invalid(const struct stack_depot_trie_node *parent,
				    const struct stack_depot_trie_node *node)
{
	const struct stack_depot_trie_node *node_parent;
	u32 base = parent ? parent->stack_len : 0;

	if (!node || !node->stack_len)
		return true;
	node_parent = trie_load_parent(node);
	if (node_parent != parent)
		return true;
	if (parent && !parent->stack_len)
		return true;
	if (stack_depot_frame_run_validate(&node->run))
		return true;
	if (node->run.nr_entries > U32_MAX - base ||
	    base > CONFIG_STACKDEPOT_MAX_FRAMES - node->run.nr_entries)
		return true;

	return node->stack_len != base + node->run.nr_entries;
}

static bool trie_node_chain_depth_invalid(const struct stack_depot_trie_node *node)
{
	unsigned int depth = 0;

	while (node) {
		const struct stack_depot_trie_node *parent;

		if (depth >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return true;
		parent = trie_load_parent(node);
		if (trie_node_depth_invalid(parent, node))
			return true;
		node = parent;
		depth++;
	}

	return false;
}

static bool
trie_parent_chain_matches_prefix(const struct stack_depot_trie_node *node,
				 const unsigned long *entries,
				 unsigned int nr_entries)
{
	const struct stack_depot_trie_node *cur;
	unsigned int depth = 0;
	unsigned int i;

	if (!node)
		return nr_entries == 0;
	if (!entries || node->stack_len != nr_entries)
		return false;

	cur = node;
	while (cur) {
		const struct stack_depot_trie_node *parent;
		unsigned int start;

		if (depth++ >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return false;
		parent = trie_load_parent(cur);
		if (stack_depot_frame_run_validate(&cur->run))
			return false;
		if (!cur->stack_len || cur->run.nr_entries > cur->stack_len)
			return false;
		if (parent) {
			if (!parent->stack_len ||
			    parent->stack_len > U32_MAX - cur->run.nr_entries)
				return false;
			if (cur->stack_len != parent->stack_len + cur->run.nr_entries)
				return false;
		} else if (cur->stack_len != cur->run.nr_entries) {
			return false;
		}

		start = cur->stack_len - cur->run.nr_entries;
		for (i = 0; i < cur->run.nr_entries; i++) {
			unsigned long frame;

			if (stack_depot_trie_node_frame(cur, i, &frame) ||
			    frame != entries[start + i])
				return false;
		}

		cur = parent;
	}

	return true;
}

static int trie_plan_split(const struct stack_depot_trie_child_array *children,
			   const struct stack_depot_trie_node *child,
			   unsigned int matched, const unsigned long *entries,
			   unsigned int nr_entries,
			   struct stack_depot_trie_node_slot *node_slots,
			   unsigned int nr_node_slots,
			   struct stack_depot_trie_child_array_slot *child_slots,
			   unsigned int nr_child_slots, size_t *new_storage_size,
			   unsigned int *nr_used, unsigned int *nr_child_used)
{
	struct stack_depot_frame_run old_tail_run;
	struct stack_depot_frame_run prefix_run;
	unsigned int new_child_used = 0;
	unsigned int new_used = 0;
	unsigned int prefix_stack_len;
	bool has_new_tail;

	if (!children || !child || !entries || !node_slots || !child_slots ||
	    !new_storage_size || !nr_used || !nr_child_used)
		return -EINVAL;
	if (!matched || matched >= child->run.nr_entries || matched > nr_entries)
		return -EINVAL;
	if (trie_node_depth_invalid(child->parent, child))
		return -EINVAL;
	if (!child->leaf_id && !child->children)
		return -EINVAL;
	if (nr_node_slots < 2 || nr_child_slots < 1)
		return -EINVAL;
	if (stack_depot_frame_run_slice(&child->run, 0, matched, &prefix_run) ||
	    stack_depot_frame_run_slice(&child->run, matched,
					child->run.nr_entries - matched,
					&old_tail_run))
		return -EINVAL;

	has_new_tail = matched < nr_entries;
	prefix_stack_len = child->parent ? child->parent->stack_len : 0;
	if (prefix_stack_len > CONFIG_STACKDEPOT_MAX_FRAMES - matched)
		return -EINVAL;
	prefix_stack_len += matched;

	node_slots[0].node = NULL;
	node_slots[0].size = __stack_depot_trie_node_size(&prefix_run);
	node_slots[1].node = NULL;
	node_slots[1].size = __stack_depot_trie_node_size(&old_tail_run);
	if (!node_slots[0].size || !node_slots[1].size)
		return -EINVAL;

	if (has_new_tail &&
	    trie_plan_append_chain(prefix_stack_len, &entries[matched],
				   nr_entries - matched, &node_slots[2],
				   nr_node_slots - 2, &child_slots[1],
				   nr_child_slots - 1, &new_used,
				   &new_child_used))
		return -EINVAL;

	child_slots[0].array = NULL;
	child_slots[0].size =
		__stack_depot_trie_child_array_size(has_new_tail ? 2 : 1);
	*new_storage_size =
		trie_child_array_size_for_capacity(children->capacity);
	if (!child_slots[0].size || !*new_storage_size)
		return -EINVAL;
	*nr_used = 2 + new_used;
	*nr_child_used = 1 + new_child_used;
	return 0;
}

int
__stack_depot_trie_insert_plan(const struct stack_depot_trie_root *root,
			       const void *parent_ptr, const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_node_slot *node_slots,
			       unsigned int nr_node_slots,
			       struct stack_depot_trie_child_array_slot *child_slots,
			       unsigned int nr_child_slots, size_t *new_storage_size,
			       unsigned int *nr_used, unsigned int *nr_child_used)
{
	const struct stack_depot_trie_node *parent = parent_ptr;
	const struct stack_depot_trie_child_array *children;
	const struct stack_depot_trie_node *child;
	unsigned int matched;
	unsigned int pos;
	bool found;

	if (!entries || !nr_entries || !node_slots || !new_storage_size ||
	    !nr_used || !nr_child_used)
		return -EINVAL;
	if ((root && parent) || (!root && !parent))
		return -EINVAL;

	for (;;) {
		if (parent && trie_node_chain_depth_invalid(parent))
			return -EINVAL;
		if (root) {
			/* Pairs with append, promote, and split publication. */
			children = smp_load_acquire(&root->children);
		} else {
			/* Pairs with append, promote, and split publication. */
			children = smp_load_acquire(&parent->children);
		}
		if (!children) {
			if (trie_plan_append_chain(parent ? parent->stack_len : 0,
						   entries, nr_entries, node_slots,
						   nr_node_slots, child_slots,
						   nr_child_slots, nr_used,
						   nr_child_used))
				return -EINVAL;
			*new_storage_size = __stack_depot_trie_child_array_size(1);
			return *new_storage_size ? 0 : -EINVAL;
		}
		if (stack_depot_trie_child_lower_bound(children, entries[0], &pos,
						       &found))
			return -EINVAL;
		if (!found) {
			if (trie_plan_append_chain(parent ? parent->stack_len : 0,
						   entries, nr_entries, node_slots,
						   nr_node_slots, child_slots,
						   nr_child_slots, nr_used,
						   nr_child_used))
				return -EINVAL;
			if (trie_child_array_can_append(children, pos)) {
				*new_storage_size = 0;
				return 0;
			}
			*new_storage_size =
				__stack_depot_trie_child_array_size(children->nr_children + 1);
			return *new_storage_size ? 0 : -EINVAL;
		}

		child = children->children[pos];
		if (trie_node_depth_invalid(parent, child))
			return -EINVAL;
		matched = __stack_depot_trie_node_match(child, entries, nr_entries);
		if (!matched || (matched == nr_entries &&
				 child->run.nr_entries == nr_entries &&
				 child->leaf_id))
			return -EINVAL;
		if (matched < child->run.nr_entries)
			return trie_plan_split(children, child, matched, entries,
					       nr_entries, node_slots, nr_node_slots,
					       child_slots, nr_child_slots,
					       new_storage_size, nr_used,
					       nr_child_used);
		if (matched == nr_entries) {
			if (child->leaf_id || !nr_node_slots)
				return -EINVAL;
			node_slots[0].node = NULL;
			node_slots[0].size = __stack_depot_trie_node_size(&child->run);
			*new_storage_size =
				trie_child_array_size_for_capacity(children->capacity);
			if (!node_slots[0].size || !*new_storage_size)
				return -EINVAL;
			*nr_used = 1;
			*nr_child_used = 0;
			return 0;
		}

		root = NULL;
		parent = child;
		entries += matched;
		nr_entries -= matched;
	}
}

struct stack_depot_trie_fetch_ctx {
	unsigned long *entries;
	unsigned int nr_entries;
};

static unsigned int trie_validate_leaf(const void *leaf,
				       const unsigned long *entries)
{
	const struct stack_depot_trie_node *node = leaf;
	size_t entries_size;
	unsigned int pos;
	unsigned int total;

	if (!node || !node->stack_len || !node->leaf_id)
		return 0;

	total = node->stack_len;
	entries_size = total * sizeof(*entries);
	pos = total;
	for (node = leaf; node; node = trie_load_parent(node)) {
		bool overlap;

		if (frame_run_validate_payload(&node->run, node->data))
			return 0;
		overlap = entries && stack_depot_ranges_overlap(entries,
							       entries_size, node->data,
							       node->run.bytes);
		if (overlap)
			return 0;
		if (node->stack_len != pos || node->run.nr_entries > pos)
			return 0;
		pos -= node->run.nr_entries;
	}

	return pos ? 0 : total;
}

static unsigned int trie_walk_frames(const void *leaf, unsigned int total,
				     trie_frame_fn_t fn, void *data)
{
	const struct stack_depot_trie_node *node;
	unsigned int seen = 0;
	unsigned int i;

	if (!fn)
		return 0;

	for (node = leaf; node; node = trie_load_parent(node)) {
		unsigned int start;

		if (node->run.nr_entries > node->stack_len)
			return 0;
		start = node->stack_len - node->run.nr_entries;
		for (i = 0; i < node->run.nr_entries; i++) {
			unsigned long frame;

			if (stack_depot_trie_node_frame(node, i, &frame))
				return 0;
			fn(start + i, frame, data);
			seen++;
		}
	}

	return seen == total ? total : 0;
}

static int trie_frame_at(const void *leaf, unsigned int index,
			 unsigned long *frame)
{
	const struct stack_depot_trie_node *node;

	if (!leaf || !frame)
		return -EINVAL;

	for (node = leaf; node; node = trie_load_parent(node)) {
		unsigned int start;

		if (node->run.nr_entries > node->stack_len)
			return -EINVAL;
		start = node->stack_len - node->run.nr_entries;
		if (index < start || index >= node->stack_len)
			continue;
		return stack_depot_trie_node_frame(node, index - start, frame);
	}

	return -EINVAL;
}

static unsigned int trie_handle_leaf(depot_stack_handle_t handle,
				     const void **leaf)
{
	u32 leaf_id;

	if (!leaf)
		return 0;
	*leaf = NULL;
	leaf_id = __stack_depot_trie_leaf_id(handle);
	if (!leaf_id)
		return 0;
	*leaf = __stack_depot_trie_side_table_lookup(leaf_id);
	if (WARN(!*leaf, "corrupt trie handle %08x\n", handle))
		return 0;
	return trie_validate_leaf(*leaf, NULL);
}

static void trie_print_frames(const void *leaf, unsigned int nr_entries,
			      int spaces)
{
	unsigned int i;

	for (i = 0; i < nr_entries; i++) {
		unsigned long frame;

		if (trie_frame_at(leaf, i, &frame))
			return;
		pr_info("%*c%pS\n", 1 + spaces, ' ', (void *)frame);
	}
}

static unsigned int trie_print_handle(depot_stack_handle_t handle, int spaces)
{
	unsigned int nr_entries;
	const void *leaf;

	rcu_read_lock_sched_notrace();
	nr_entries = trie_handle_leaf(handle, &leaf);
	if (nr_entries)
		trie_print_frames(leaf, nr_entries, spaces);
	rcu_read_unlock_sched_notrace();

	return nr_entries;
}

static int
trie_snprint_frames(char *buf, size_t size, const void *leaf,
		    unsigned int nr_entries, int spaces)
{
	unsigned int generated;
	unsigned int total = 0;
	unsigned int i;

	for (i = 0; i < nr_entries && size; i++) {
		unsigned long frame;

		if (trie_frame_at(leaf, i, &frame))
			break;
		generated = snprintf(buf, size, "%*c%pS\n", 1 + spaces, ' ',
				     (void *)frame);
		total += generated;
		if (generated >= size) {
			buf += size;
			size = 0;
		} else {
			buf += generated;
			size -= generated;
		}
	}

	return total;
}

static int
trie_snprint_handle(depot_stack_handle_t handle, char *buf, size_t size,
		    int spaces)
{
	unsigned int nr_entries;
	const void *leaf;
	int ret = 0;

	rcu_read_lock_sched_notrace();
	nr_entries = trie_handle_leaf(handle, &leaf);
	if (nr_entries)
		ret = trie_snprint_frames(buf, size, leaf, nr_entries, spaces);
	rcu_read_unlock_sched_notrace();

	return ret;
}

static void trie_fetch_frame(unsigned int index, unsigned long frame, void *data)
{
	struct stack_depot_trie_fetch_ctx *ctx = data;

	ctx->entries[index] = frame;
	ctx->nr_entries++;
}

unsigned int
__stack_depot_trie_walk_frames(const void *leaf, trie_frame_fn_t fn, void *data)
{
	unsigned int total;

	total = trie_validate_leaf(leaf, NULL);
	if (!total)
		return 0;

	return trie_walk_frames(leaf, total, fn, data);
}

unsigned int
__stack_depot_trie_fetch_into(const void *leaf, unsigned long *entries,
			      unsigned int max_entries)
{
	struct stack_depot_trie_fetch_ctx ctx;
	unsigned int total;

	if (!entries)
		return 0;
	total = trie_validate_leaf(leaf, entries);
	if (!total)
		return 0;
	if (max_entries < total)
		return 0;

	ctx.entries = entries;
	ctx.nr_entries = 0;
	if (trie_walk_frames(leaf, total, trie_fetch_frame, &ctx) != total)
		return 0;

	kmsan_unpoison_memory(entries, total * sizeof(*entries));
	return total;
}

static unsigned int trie_fetch_leaf(const void *leaf, unsigned long *entries,
				    unsigned int max_entries)
{
	return __stack_depot_trie_fetch_into(leaf, entries, max_entries);
}

unsigned int
__stack_depot_trie_fetch_handle_into(depot_stack_handle_t handle,
				     unsigned long *entries,
				     unsigned int max_entries)
{
	const void *leaf;
	u32 leaf_id;
	unsigned int nr_entries;

	if (!handle || !entries || !max_entries)
		return 0;

	leaf_id = __stack_depot_trie_leaf_id(handle);
	if (!leaf_id)
		return 0;

	rcu_read_lock_sched_notrace();
	leaf = __stack_depot_trie_side_table_lookup(leaf_id);
	if (WARN(!leaf, "corrupt trie handle %08x\n", handle)) {
		rcu_read_unlock_sched_notrace();
		return 0;
	}
	nr_entries = trie_fetch_leaf(leaf, entries, max_entries);
	rcu_read_unlock_sched_notrace();

	return nr_entries;
}

static unsigned int trie_child_array_capacity(unsigned int nr_children)
{
	if (!nr_children)
		return 0;
	return roundup_pow_of_two(nr_children);
}

static unsigned int trie_child_array_storage_capacity(size_t storage_size)
{
	if (storage_size < sizeof(struct stack_depot_trie_child_array))
		return 0;
	storage_size -= sizeof(struct stack_depot_trie_child_array);
	return storage_size / sizeof(struct stack_depot_trie_node *);
}

static size_t trie_child_array_size_for_capacity(unsigned int capacity)
{
	size_t size;
	size_t bytes;

	if (check_mul_overflow((size_t)capacity,
			       sizeof(struct stack_depot_trie_node *), &bytes))
		return 0;
	size = sizeof(struct stack_depot_trie_child_array);
	if (check_add_overflow(size, bytes, &size))
		return 0;

	return ALIGN(size, sizeof(unsigned long));
}

size_t __stack_depot_trie_child_array_size(unsigned int nr_children)
{
	unsigned int capacity = trie_child_array_capacity(nr_children);

	return trie_child_array_size_for_capacity(capacity);
}

int __stack_depot_trie_child_array_init(void *storage, size_t storage_size,
					const void * const *children,
					unsigned int nr_children)
{
	struct stack_depot_trie_child_array *array = storage;
	const struct stack_depot_trie_node * const *nodes =
		(const struct stack_depot_trie_node * const *)children;
	unsigned int capacity;
	unsigned long last = 0;
	unsigned int i;

	if (!array || storage_size < __stack_depot_trie_child_array_size(nr_children))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)array, __alignof__(*array)))
		return -EINVAL;
	if (nr_children && !nodes)
		return -EINVAL;
	capacity = trie_child_array_storage_capacity(storage_size);
	if (capacity < nr_children)
		return -EINVAL;

	for (i = 0; i < nr_children; i++) {
		unsigned long frame;
		size_t size;

		if (stack_depot_trie_node_first_frame(nodes[i], &frame))
			return -EINVAL;
		size = __stack_depot_trie_node_size(&nodes[i]->run);
		if (!size)
			return -EINVAL;
		if (stack_depot_ranges_overlap(array, storage_size, nodes[i], size))
			return -EINVAL;
		/* Child key zero is reserved so NULL lookup remains unambiguous. */
		if (!frame || (i && frame <= last))
			return -EINVAL;
		last = frame;
	}

	array->nr_children = nr_children;
	array->capacity = capacity;
	for (i = 0; i < nr_children; i++)
		array->children[i] = nodes[i];

	return 0;
}

int __stack_depot_trie_split_child_array_init(void *storage, size_t storage_size,
					      const void *old_tail,
					      const void *new_head)
{
	const void *children[2];
	unsigned long new_frame;
	unsigned long old_frame;

	if (!old_tail)
		return -EINVAL;
	if (!new_head) {
		children[0] = old_tail;
		return __stack_depot_trie_child_array_init(storage, storage_size,
						       children, 1);
	}

	if (stack_depot_trie_node_first_frame(old_tail, &old_frame) ||
	    stack_depot_trie_node_first_frame(new_head, &new_frame) ||
	    old_frame == new_frame)
		return -EINVAL;
	if (old_frame < new_frame) {
		children[0] = old_tail;
		children[1] = new_head;
	} else {
		children[0] = new_head;
		children[1] = old_tail;
	}

	return __stack_depot_trie_child_array_init(storage, storage_size, children, 2);
}

int __stack_depot_trie_split_tail_plan(const unsigned long *entries,
				       unsigned int nr_entries,
				       const struct stack_depot_trie_node_slot *node_slots,
				       unsigned int nr_node_slots,
				       const struct stack_depot_trie_child_array_slot *child_slots,
				       unsigned int nr_child_slots,
				       unsigned int *nr_runs)
{
	unsigned int pos = 0;
	unsigned int runs = 0;
	unsigned int child_slots_needed;
	unsigned int i;

	if (!entries || !nr_entries || nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES ||
	    !node_slots || !nr_runs)
		return -EINVAL;

	while (pos < nr_entries) {
		const struct stack_depot_trie_node_slot *slot;
		struct stack_depot_frame_run run;
		size_t size;

		if (__stack_depot_frame_run_init(&entries[pos], nr_entries - pos,
						 &run))
			return -EINVAL;
		if (runs >= nr_node_slots)
			return -EINVAL;
		slot = &node_slots[runs];
		if (!slot->node)
			return -EINVAL;
		size = __stack_depot_trie_node_size(&run);
		if (!size || slot->size < size)
			return -EINVAL;
		if (!IS_ALIGNED((unsigned long)slot->node,
				__alignof__(struct stack_depot_trie_node)))
			return -EINVAL;

		pos += run.nr_entries;
		runs++;
	}

	child_slots_needed = runs > 1 ? runs - 1 : 0;
	if (child_slots_needed) {
		if (!child_slots || nr_child_slots < child_slots_needed)
			return -EINVAL;
		for (i = 0; i < child_slots_needed; i++) {
			size_t size = __stack_depot_trie_child_array_size(1);

			if (!child_slots[i].array || child_slots[i].size < size)
				return -EINVAL;
			if (!IS_ALIGNED((unsigned long)child_slots[i].array,
					__alignof__(struct stack_depot_trie_child_array)))
				return -EINVAL;
		}
	}

	*nr_runs = runs;
	return 0;
}

int __stack_depot_trie_split_precheck(struct stack_depot_trie_root *root,
				      const void *parent_ptr,
				      const struct stack_depot_trie_node_slot *node_slots,
				      unsigned int nr_node_slots,
				      const struct stack_depot_trie_child_array_slot *child_slots,
				      unsigned int nr_child_slots,
				      void *new_storage, size_t new_storage_size)
{
	struct stack_depot_trie_node *parent = (void *)parent_ptr;
	const struct stack_depot_trie_child_array **slot;
	const struct stack_depot_trie_child_array *children;
	unsigned int i;
	size_t size;

	if (!new_storage || !new_storage_size ||
	    (nr_node_slots && !node_slots) || (nr_child_slots && !child_slots))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_storage,
			__alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;

	for (i = 0; i < nr_node_slots; i++) {
		const struct stack_depot_trie_node_slot *node_slot = &node_slots[i];

		if (!node_slot->node || !node_slot->size)
			return -EINVAL;
		if (!IS_ALIGNED((unsigned long)node_slot->node,
				__alignof__(struct stack_depot_trie_node)))
			return -EINVAL;
		if (parent &&
		    trie_ancestor_overlaps(parent, node_slot->node, node_slot->size))
			return -EINVAL;
		if (trie_node_slot_overlaps(node_slots, i, node_slot->node, node_slot->size))
			return -EINVAL;
	}

	for (i = 0; i < nr_child_slots; i++) {
		const struct stack_depot_trie_child_array_slot *child_slot =
			&child_slots[i];
		void *array = child_slot->array;
		size_t slot_size = child_slot->size;

		if (!array || !slot_size)
			return -EINVAL;
		if (!IS_ALIGNED((unsigned long)array,
				__alignof__(struct stack_depot_trie_child_array)))
			return -EINVAL;
		if (parent &&
		    trie_ancestor_overlaps(parent, array, slot_size))
			return -EINVAL;
		if (trie_child_slot_overlaps(child_slots, i, array, slot_size))
			return -EINVAL;
	}

	for (i = 0; i < nr_node_slots; i++) {
		if (trie_child_slot_overlaps(child_slots, nr_child_slots,
					     node_slots[i].node, node_slots[i].size))
			return -EINVAL;
	}
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, new_storage,
				    new_storage_size) ||
	    trie_child_slot_overlaps(child_slots, nr_child_slots, new_storage,
				     new_storage_size))
		return -EINVAL;

	slot = trie_publish_slot(root, parent);
	if (!slot)
		return -EINVAL;
	if (stack_depot_ranges_overlap(new_storage, new_storage_size, slot,
				       sizeof(*slot)))
		return -EINVAL;
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, slot, sizeof(*slot)) ||
	    trie_child_slot_overlaps(child_slots, nr_child_slots, slot, sizeof(*slot)))
		return -EINVAL;
	if (parent && trie_ancestor_overlaps(parent, new_storage, new_storage_size))
		return -EINVAL;

	/* Pairs with append, promote, and future split publication. */
	children = smp_load_acquire(slot);
	if (!children)
		return -EINVAL;
	size = trie_child_array_size_for_capacity(children->capacity);
	if (!size || new_storage_size < size)
		return -EINVAL;
	if (stack_depot_ranges_overlap(children, size, new_storage,
				       new_storage_size))
		return -EINVAL;
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, children, size) ||
	    trie_child_slot_overlaps(child_slots, nr_child_slots, children, size))
		return -EINVAL;
	if (trie_node_slots_subtree_overlap(children, parent, node_slots, nr_node_slots))
		return -EINVAL;
	if (trie_child_slots_subtree_overlap(children, parent, child_slots, nr_child_slots))
		return -EINVAL;
	if (trie_child_array_subtree_overlaps(children, parent, new_storage,
					      new_storage_size))
		return -EINVAL;

	return 0;
}

static bool
trie_split_subtree_overlaps(const struct stack_depot_trie_node *child,
			    const void *ptr, size_t size)
{
	if (trie_ancestor_overlaps(child, ptr, size))
		return true;
	return trie_child_array_subtree_overlaps(child->children, child, ptr,
						 size);
}

static bool
trie_split_slots_overlap(const struct stack_depot_trie_node *child,
			 const struct stack_depot_trie_node_slot *node_slots,
			 unsigned int nr_node_slots,
			 const struct stack_depot_trie_child_array_slot *child_slots,
			 unsigned int nr_child_slots)
{
	unsigned int i;

	for (i = 0; i < nr_node_slots; i++) {
		const struct stack_depot_trie_node_slot *slot = &node_slots[i];

		if (trie_split_subtree_overlaps(child, slot->node, slot->size))
			return true;
		if (trie_node_slot_overlaps(node_slots, i, slot->node,
					    slot->size))
			return true;
		if (trie_child_slot_overlaps(child_slots, nr_child_slots,
					     slot->node, slot->size))
			return true;
	}

	for (i = 0; i < nr_child_slots; i++) {
		const struct stack_depot_trie_child_array_slot *slot =
			&child_slots[i];

		if (trie_split_subtree_overlaps(child, slot->array, slot->size))
			return true;
		if (trie_child_slot_overlaps(child_slots, i, slot->array,
					     slot->size))
			return true;
	}

	return false;
}

static int
trie_split_subtree_precheck(const struct stack_depot_trie_node *child,
			    unsigned int matched, u32 leaf_id,
			    const unsigned long *entries, unsigned int nr_entries,
			    const struct stack_depot_trie_node_slot *node_slots,
			    unsigned int nr_node_slots,
			    const struct stack_depot_trie_child_array_slot *child_slots,
			    unsigned int nr_child_slots, unsigned int *new_runs)
{
	struct stack_depot_frame_run old_tail_run;
	struct stack_depot_frame_run prefix_run;
	const unsigned long *tail_entries;
	unsigned int child_slots_needed;
	unsigned int slots_needed;
	unsigned int tail_child_slots;
	unsigned int tail_node_slots;
	unsigned int tail_len;
	bool has_new_tail;
	size_t size;
	int ret;

	if (!child || !leaf_id || !entries || !nr_entries || !node_slots ||
	    !child_slots || !new_runs)
		return -EINVAL;
	if (!matched || matched >= child->run.nr_entries ||
	    matched > nr_entries)
		return -EINVAL;
	if (!child->leaf_id && !child->children)
		return -EINVAL;
	if (stack_depot_frame_run_slice(&child->run, 0, matched, &prefix_run))
		return -EINVAL;
	tail_len = child->run.nr_entries - matched;
	if (stack_depot_frame_run_slice(&child->run, matched, tail_len, &old_tail_run))
		return -EINVAL;

	has_new_tail = matched < nr_entries;
	*new_runs = 0;
	if (has_new_tail) {
		tail_entries = &entries[matched];
		tail_len = nr_entries - matched;
		tail_node_slots = nr_node_slots > 2 ? nr_node_slots - 2 : 0;
		tail_child_slots = nr_child_slots > 1 ? nr_child_slots - 1 : 0;
		ret = __stack_depot_trie_split_tail_plan(tail_entries, tail_len,
							 &node_slots[2], tail_node_slots,
							 tail_child_slots ? &child_slots[1] : NULL,
							 tail_child_slots, new_runs);
		if (ret)
			return ret;
	}

	slots_needed = 2 + *new_runs;
	child_slots_needed = 1 + (*new_runs ? *new_runs - 1 : 0);
	if (nr_node_slots < slots_needed || nr_child_slots < child_slots_needed)
		return -EINVAL;

	size = __stack_depot_trie_node_size(&prefix_run);
	if (!node_slots[0].node || node_slots[0].size < size)
		return -EINVAL;
	size = __stack_depot_trie_node_size(&old_tail_run);
	if (!node_slots[1].node || node_slots[1].size < size)
		return -EINVAL;
	size = __stack_depot_trie_child_array_size(has_new_tail ? 2 : 1);
	if (!child_slots[0].array || child_slots[0].size < size)
		return -EINVAL;
	if (trie_split_slots_overlap(child, node_slots, slots_needed,
				     child_slots, child_slots_needed))
		return -EINVAL;

	return 0;
}

static int trie_split_subtree_prepare(const void *child_ptr, unsigned int matched,
				      u32 leaf_id, const unsigned long *entries,
				      unsigned int nr_entries,
				      const struct stack_depot_trie_node_slot *node_slots,
				      unsigned int nr_node_slots,
				      const struct stack_depot_trie_child_array_slot *child_slots,
				      unsigned int nr_child_slots, u32 *scratch,
				      unsigned int nr_scratch,
				      const struct stack_depot_trie_publish_prepare *prepare,
				      const void **prefix,
				      const void **tail, unsigned int *nr_used)
{
	const struct stack_depot_trie_node *child = child_ptr;
	const unsigned long *tail_entries;
	const void *new_head = NULL;
	const void *new_tail = NULL;
	struct stack_depot_trie_leaf_update updates[2];
	struct stack_depot_trie_node *old_tail;
	struct stack_depot_trie_node *pref;
	unsigned int chain_used = 0;
	unsigned int nr_updates = 0;
	u32 prefix_leaf_id;
	void *split_array;
	size_t split_array_size;
	unsigned int new_runs;
	unsigned int tail_len;
	bool has_new_tail;
	int ret;

	if (!prefix || !tail || !nr_used)
		return -EINVAL;
	ret = trie_split_subtree_precheck(child, matched, leaf_id, entries,
					  nr_entries, node_slots, nr_node_slots,
					  child_slots, nr_child_slots,
					  &new_runs);
	if (ret)
		return ret;

	pref = node_slots[0].node;
	old_tail = node_slots[1].node;
	has_new_tail = matched < nr_entries;
	prefix_leaf_id = has_new_tail ? 0 : leaf_id;
	ret = __stack_depot_trie_node_init_slice(pref, node_slots[0].size,
						 child->parent, prefix_leaf_id,
						 child, 0, matched);
	if (ret)
		return ret;
	tail_len = child->run.nr_entries - matched;
	ret = __stack_depot_trie_node_init_slice(old_tail, node_slots[1].size,
						 pref, child->leaf_id, child,
						 matched, tail_len);
	if (ret)
		return ret;

	if (has_new_tail) {
		tail_entries = &entries[matched];
		tail_len = nr_entries - matched;
		ret = __stack_depot_trie_append_chain(pref, leaf_id, tail_entries,
						      tail_len, &node_slots[2], nr_node_slots - 2,
						      &child_slots[1], nr_child_slots - 1,
						      scratch, nr_scratch, &new_head, &new_tail,
						      &chain_used);
		if (ret)
			return ret;
	}
	split_array = child_slots[0].array;
	split_array_size = child_slots[0].size;
	ret = __stack_depot_trie_split_child_array_init(split_array, split_array_size,
							old_tail, new_head);
	if (ret)
		return ret;
	if (child->leaf_id) {
		updates[nr_updates].leaf_id = child->leaf_id;
		updates[nr_updates].leaf = old_tail;
		nr_updates++;
	}
	updates[nr_updates].leaf_id = leaf_id;
	updates[nr_updates].leaf = has_new_tail ? new_tail : pref;
	nr_updates++;
	if (prepare) {
		if (!prepare->fn)
			return -EINVAL;
		ret = prepare->fn(updates, nr_updates, prepare->ctx);
		if (ret) {
			memset(split_array, 0, split_array_size);
			return ret;
		}
	}

	old_tail->children = child->children;
	pref->children = child_slots[0].array;
	trie_reparent_children(old_tail);
	*prefix = pref;
	*tail = has_new_tail ? new_tail : pref;
	*nr_used = 2 + chain_used;
	return 0;
}

int __stack_depot_trie_split_subtree(const void *child, unsigned int matched,
				     u32 leaf_id, const unsigned long *entries,
				     unsigned int nr_entries,
				     const struct stack_depot_trie_node_slot *node_slots,
				     unsigned int nr_node_slots,
				     const struct stack_depot_trie_child_array_slot *child_slots,
				     unsigned int nr_child_slots, u32 *scratch,
				     unsigned int nr_scratch, const void **prefix,
				     const void **tail, unsigned int *nr_used)
{
	return trie_split_subtree_prepare(child, matched, leaf_id, entries,
					  nr_entries, node_slots, nr_node_slots,
					  child_slots, nr_child_slots, scratch,
					  nr_scratch, NULL, prefix, tail,
					  nr_used);
}

static int trie_split_child(struct stack_depot_trie_root *root,
			    struct stack_depot_trie_node *parent,
			    const struct stack_depot_trie_node *child,
			    unsigned int matched, u32 leaf_id,
			    const unsigned long *entries,
			    unsigned int nr_entries,
			    const struct stack_depot_trie_node_slot *node_slots,
			    unsigned int nr_node_slots,
			    const struct stack_depot_trie_child_array_slot *child_slots,
			    unsigned int nr_child_slots, u32 *scratch,
			    unsigned int nr_scratch, void *new_storage,
			    size_t new_storage_size,
			    const struct stack_depot_trie_publish_prepare *prepare,
			    const void **tail,
			    unsigned int *nr_used)
{
	const struct stack_depot_trie_child_array **publish_slot;
	const struct stack_depot_trie_child_array *old_array;
	const void *prefix;
	void *storage = new_storage;
	size_t child_size;
	size_t storage_size = new_storage_size;
	unsigned int pos;
	unsigned int used;
	int ret;

	if (!child || !tail || !nr_used)
		return -EINVAL;
	if (child->parent != parent)
		return -EINVAL;

	ret = __stack_depot_trie_split_precheck(root, parent, node_slots,
						nr_node_slots, child_slots,
						nr_child_slots, new_storage,
						new_storage_size);
	if (ret)
		return ret;
	publish_slot = trie_publish_slot(root, parent);
	if (!publish_slot)
		return -EINVAL;

	/* Pairs with append, promote, and split publication. */
	old_array = smp_load_acquire(publish_slot);
	ret = trie_child_array_replace_precheck(old_array, child, storage, storage_size, &pos);
	if (ret)
		return ret;
	child_size = __stack_depot_trie_node_size(&child->run);
	if (!child_size)
		return -EINVAL;

	ret = trie_split_subtree_prepare(child, matched, leaf_id, entries,
					 nr_entries, node_slots, nr_node_slots,
					 child_slots, nr_child_slots, scratch,
					 nr_scratch, prepare, &prefix,
					 tail, &used);
	if (ret)
		return ret;

	trie_child_array_replace_at(old_array, prefix, new_storage,
				    new_storage_size, pos);
	/* Publish the fully initialized replacement array last. */
	smp_store_release(publish_slot, new_storage);
	if (prepare && prepare->retire_locked)
		trie_retire_object_node_locked(old_array, child, child_size);
	else
		trie_retire_object_node(old_array, child, child_size);
	*nr_used = used;
	return 0;
}

static int
stack_depot_trie_child_lower_bound(const struct stack_depot_trie_child_array *array,
				   unsigned long frame, unsigned int *pos, bool *found)
{
	unsigned int left = 0;
	unsigned int right;

	if (!array || !pos || !found)
		return -EINVAL;
	*pos = 0;
	*found = false;

	/* Pairs with in-place append publication's smp_store_release(). */
	right = smp_load_acquire(&array->nr_children);
	while (left < right) {
		unsigned int mid = left + (right - left) / 2;
		unsigned long mid_frame;

		if (stack_depot_trie_node_first_frame(array->children[mid], &mid_frame))
			return -EINVAL;
		if (mid_frame < frame) {
			left = mid + 1;
		} else if (mid_frame > frame) {
			right = mid;
		} else {
			*pos = mid;
			*found = true;
			return 0;
		}
	}

	*pos = left;
	return 0;
}

const void *
__stack_depot_trie_child_array_find(const void *storage, unsigned long frame)
{
	const struct stack_depot_trie_child_array *array = storage;
	unsigned int pos;
	bool found;

	if (!array)
		return NULL;

	if (stack_depot_trie_child_lower_bound(array, frame, &pos, &found) ||
	    !found)
		return NULL;

	return array->children[pos];
}

int
__stack_depot_trie_child_array_insert(const void *old_storage, const void *child,
				      void *new_storage, size_t new_storage_size)
{
	const struct stack_depot_trie_child_array *old_array = old_storage;
	struct stack_depot_trie_child_array *new_array = new_storage;
	const struct stack_depot_trie_node *node = child;
	unsigned int nr_old;
	unsigned int pos;
	unsigned int i;
	unsigned long frame;
	size_t node_size;
	size_t old_size;
	bool overlaps;
	bool found;

	if (!node || !new_array || stack_depot_trie_node_first_frame(node, &frame))
		return -EINVAL;
	node_size = __stack_depot_trie_node_size(&node->run);
	if (!node_size)
		return -EINVAL;
	if (stack_depot_ranges_overlap(new_array, new_storage_size, node, node_size))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_array, __alignof__(*new_array)))
		return -EINVAL;
	if (!frame)
		return -EINVAL;
	if (old_array == new_array)
		return -EINVAL;
	if (old_array && !IS_ALIGNED((unsigned long)old_array, __alignof__(*old_array)))
		return -EINVAL;

	nr_old = old_array ? old_array->nr_children : 0;
	if (new_storage_size < __stack_depot_trie_child_array_size(nr_old + 1))
		return -EINVAL;
	old_size = old_array ? trie_child_array_size_for_capacity(old_array->capacity) : 0;
	overlaps = old_array && stack_depot_ranges_overlap(old_array, old_size,
							  new_array, new_storage_size);
	if (overlaps)
		return -EINVAL;

	if (old_array) {
		if (stack_depot_trie_child_lower_bound(old_array, frame, &pos,
						       &found))
			return -EINVAL;
		if (found)
			return -EINVAL;
	} else {
		/* NULL old array means the new child must be inserted at the start. */
		pos = 0;
	}

	new_array->nr_children = nr_old + 1;
	new_array->capacity = trie_child_array_storage_capacity(new_storage_size);
	if (old_array) {
		for (i = 0; i < pos; i++)
			new_array->children[i] = old_array->children[i];
	}
	new_array->children[pos] = node;
	if (old_array) {
		for (i = pos; i < nr_old; i++)
			new_array->children[i + 1] = old_array->children[i];
	}

	return 0;
}

unsigned int stack_depot_fetch(depot_stack_handle_t handle,
			       unsigned long **entries)
{
	struct stack_record *stack;

	*entries = NULL;
	/*
	 * Let KMSAN know *entries is initialized. This shall prevent false
	 * positive reports if instrumented code accesses it.
	 */
	kmsan_unpoison_memory(entries, sizeof(*entries));

	if (!handle || stack_depot_disabled)
		return 0;
	if (WARN_ON_ONCE(__stack_depot_trie_leaf_id(handle)))
		return 0;

	stack = depot_fetch_stack(handle);
	/*
	 * Should never be NULL, otherwise this is a use-after-put (or just a
	 * corrupt handle).
	 */
	if (WARN(!stack, "corrupt handle or use after stack_depot_put()"))
		return 0;

	*entries = stack->entries;
	return stack->size;
}
EXPORT_SYMBOL_GPL(stack_depot_fetch);

unsigned int stack_depot_fetch_into(depot_stack_handle_t handle,
				    unsigned long *entries,
				    unsigned int max_entries)
{
	struct stack_record *stack;
	unsigned int nr_entries;

	if (!handle || !entries || !max_entries)
		return 0;
	if (stack_depot_disabled)
		return 0;
	if (__stack_depot_trie_leaf_id(handle))
		return __stack_depot_trie_fetch_handle_into(handle, entries,
						      max_entries);

	rcu_read_lock_sched_notrace();
	stack = depot_fetch_stack(handle);
	if (!stack) {
		rcu_read_unlock_sched_notrace();
		return 0;
	}
	nr_entries = stack->size;
	if (!nr_entries || nr_entries > max_entries) {
		rcu_read_unlock_sched_notrace();
		return 0;
	}

	memcpy(entries, stack->entries, nr_entries * sizeof(*entries));
	rcu_read_unlock_sched_notrace();
	kmsan_unpoison_memory(entries, nr_entries * sizeof(*entries));
	return nr_entries;
}
EXPORT_SYMBOL_GPL(stack_depot_fetch_into);

void stack_depot_put(depot_stack_handle_t handle)
{
	struct stack_record *stack;

	if (!handle || stack_depot_disabled)
		return;
	if (__stack_depot_trie_leaf_id(handle))
		return;

	stack = depot_fetch_stack(handle);
	/*
	 * Should always be able to find the stack record, otherwise this is an
	 * unbalanced put attempt (or corrupt handle).
	 */
	if (WARN(!stack, "corrupt handle or unbalanced %s()", __func__))
		return;

	if (refcount_dec_and_test(&stack->count))
		depot_free_stack(stack);
}
EXPORT_SYMBOL_GPL(stack_depot_put);

void stack_depot_print(depot_stack_handle_t stack)
{
	unsigned long *entries;
	unsigned int nr_entries;

	if (__stack_depot_trie_leaf_id(stack)) {
		trie_print_handle(stack, 0);
		return;
	}

	nr_entries = stack_depot_fetch(stack, &entries);
	if (nr_entries > 0)
		stack_trace_print(entries, nr_entries, 0);
}
EXPORT_SYMBOL_GPL(stack_depot_print);

int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
			int spaces)
{
	unsigned long *entries;
	unsigned int nr_entries;

	if (__stack_depot_trie_leaf_id(handle))
		return trie_snprint_handle(handle, buf, size, spaces);

	nr_entries = stack_depot_fetch(handle, &entries);
	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
						spaces) : 0;
}
EXPORT_SYMBOL_GPL(stack_depot_snprint);

depot_stack_handle_t __must_check stack_depot_set_extra_bits(depot_stack_handle_t handle,
							     unsigned int extra_bits)
{
	union handle_parts parts = { .handle = handle };

	/* Do not set extra bits on empty handles. */
	parts.extra = 0;
	if (!parts.handle)
		return 0;

	parts.extra = extra_bits;
	return parts.handle;
}
EXPORT_SYMBOL(stack_depot_set_extra_bits);

unsigned int stack_depot_get_extra_bits(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };

	return parts.extra;
}
EXPORT_SYMBOL(stack_depot_get_extra_bits);

static int stats_show(struct seq_file *seq, void *v)
{
	/*
	 * data race ok: These are just statistics counters, and approximate
	 * statistics are ok for debugging.
	 */
	seq_printf(seq, "pools: %d\n", data_race(pools_num));
	/* data race ok: counters are approximate debugfs statistics. */
	for (int i = 0; i < DEPOT_COUNTER_COUNT; i++)
		seq_printf(seq, "%s: %ld\n", counter_names[i],
			   data_race(counters[i])); /* Statistic. */
	seq_printf(seq, "trie_side_table_bytes: %zu\n",
		   __stack_depot_trie_side_table_bytes());

	return 0;
}
DEFINE_SHOW_ATTRIBUTE(stats);

static int depot_debugfs_init(void)
{
	struct dentry *dir;

	if (stack_depot_disabled)
		return 0;

	dir = debugfs_create_dir("stackdepot", NULL);
	debugfs_create_file("stats", 0444, dir, NULL, &stats_fops);
	return 0;
}
late_initcall(depot_debugfs_init);
