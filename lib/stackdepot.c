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

#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/kmsan.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/poison.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
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
static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
static bool __stack_depot_early_init_passed __initdata;

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
	u32 stack_len;
	struct stack_depot_frame_run run;
	unsigned char data[];
};

struct stack_depot_trie_child_array {
	unsigned int nr_children;
	const struct stack_depot_trie_node *children[];
};

/* Hash table of stored stack records. */
static struct list_head *stack_table;
/* Fixed order of the number of table buckets. Used when KASAN is enabled. */
static unsigned int stack_bucket_number_order;
/* Hash mask for indexing the table. */
static unsigned int stack_hash_mask;

/* Array of memory regions that store stack records. */
static void **stack_pools;
/* Newly allocated pool that is not yet added to stack_pools. */
static void *new_pool;
/* Number of pools in stack_pools. */
static int pools_num;
/* Offset to the unused space in the currently used pool. */
static size_t pool_offset = DEPOT_POOL_SIZE;
/* Freelist of stack records within stack_pools. */
static LIST_HEAD(free_stacks);
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

static const void ***trie_side_table_chunks;
static DEFINE_RAW_SPINLOCK(trie_side_table_lock);
static unsigned int trie_side_table_high_water;
static unsigned int trie_side_table_nr_chunks;
static unsigned int trie_side_table_top_size;
static u32 trie_side_table_next_id;
static bool trie_side_table_initialized;

static unsigned int trie_side_table_top_index(u32 id)
{
	return (id - 1) >> STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS;
}

static unsigned int trie_side_table_slot_index(u32 id)
{
	return (id - 1) & (STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE - 1);
}

static const void **trie_side_table_load_chunk(unsigned int top)
{
	/* Pairs with trie_side_table_publish_chunk(). */
	return smp_load_acquire(&trie_side_table_chunks[top]);
}

static void trie_side_table_publish_chunk(unsigned int top, const void **chunk)
{
	/* Pairs with trie_side_table_load_chunk(). */
	smp_store_release(&trie_side_table_chunks[top], chunk);
}

static const void *
trie_side_table_load_entry(const void **chunk, unsigned int slot)
{
	/* Pairs with trie_side_table_store_entry(). */
	return smp_load_acquire(&chunk[slot]);
}

static void
trie_side_table_store_entry(const void **chunk, unsigned int slot, const void *entry)
{
	/* Pairs with trie_side_table_load_entry(). */
	smp_store_release(&chunk[slot], entry);
}

static void trie_side_table_clear_entry(const void **chunk, unsigned int slot)
{
	WRITE_ONCE(chunk[slot], NULL);
}

int __stack_depot_trie_side_table_init(gfp_t gfp_flags)
{
	u32 max_leaf_id;

	if (READ_ONCE(trie_side_table_initialized))
		return 0;

	max_leaf_id = __stack_depot_trie_max_leaf_id();
	if (!max_leaf_id)
		return -EINVAL;

	trie_side_table_top_size =
		DIV_ROUND_UP(max_leaf_id, STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE);
	trie_side_table_chunks =
		kvcalloc(trie_side_table_top_size, sizeof(*trie_side_table_chunks),
			 gfp_flags);
	if (!trie_side_table_chunks)
		return -ENOMEM;

	trie_side_table_high_water = 0;
	trie_side_table_nr_chunks = 0;
	trie_side_table_next_id = 0;
	WRITE_ONCE(trie_side_table_initialized, true);
	return 0;
}

void __stack_depot_trie_side_table_destroy(void)
{
	unsigned int i;

	if (!READ_ONCE(trie_side_table_initialized))
		return;

	for (i = 0; i < trie_side_table_high_water; i++)
		kfree(trie_side_table_chunks[i]);
	kvfree(trie_side_table_chunks);
	trie_side_table_chunks = NULL;
	trie_side_table_high_water = 0;
	trie_side_table_nr_chunks = 0;
	trie_side_table_top_size = 0;
	trie_side_table_next_id = 0;
	WRITE_ONCE(trie_side_table_initialized, false);
}

bool __stack_depot_trie_side_table_prealloc_needed(void)
{
	unsigned long flags;
	bool needed;
	u32 id;
	unsigned int top;

	if (!READ_ONCE(trie_side_table_initialized))
		return false;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	id = READ_ONCE(trie_side_table_next_id) + 1;
	if (!id || id > __stack_depot_trie_max_leaf_id()) {
		needed = false;
		goto out;
	}

	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size) {
		needed = false;
		goto out;
	}

	needed = !trie_side_table_load_chunk(top);
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return needed;
}

void *__stack_depot_trie_side_table_prealloc(gfp_t gfp_flags)
{
	return kcalloc(STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE,
		       sizeof(*trie_side_table_chunks[0]), gfp_flags);
}

void __stack_depot_trie_side_table_free_prealloc(void *prealloc)
{
	kfree(prealloc);
}

u32 __stack_depot_trie_side_table_alloc_id(void **prealloc)
{
	const void **chunk;
	unsigned long flags;
	u32 id;
	unsigned int top;

	if (!READ_ONCE(trie_side_table_initialized))
		return 0;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	id = trie_side_table_next_id + 1;
	if (!id || id > __stack_depot_trie_max_leaf_id())
		goto fail;

	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size)
		goto fail;

	chunk = trie_side_table_load_chunk(top);
	if (!chunk) {
		if (!prealloc || !*prealloc)
			goto fail;
		chunk = *prealloc;
		*prealloc = NULL;
		trie_side_table_publish_chunk(top, chunk);
		trie_side_table_nr_chunks++;
		if (trie_side_table_high_water < top + 1)
			trie_side_table_high_water = top + 1;
	}

	WRITE_ONCE(trie_side_table_next_id, id);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return id;
fail:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return 0;
}

void __stack_depot_trie_side_table_revoke_latest(u32 id)
{
	const void **chunk;
	unsigned long flags;
	unsigned int slot;
	unsigned int top;

	if (!READ_ONCE(trie_side_table_initialized) || !id ||
	    id != READ_ONCE(trie_side_table_next_id))
		return;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id != trie_side_table_next_id)
		goto out;
	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size)
		goto out;

	chunk = trie_side_table_load_chunk(top);
	if (!chunk)
		goto out;

	slot = trie_side_table_slot_index(id);
	trie_side_table_clear_entry(chunk, slot);
	WRITE_ONCE(trie_side_table_next_id, id - 1);
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
}

void __stack_depot_trie_side_table_restore(u32 id, const void *entry)
{
	const void **chunk;
	unsigned long flags;
	unsigned int top;

	if (!READ_ONCE(trie_side_table_initialized) || !id)
		return;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id > trie_side_table_next_id)
		goto out;
	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size)
		goto out;

	chunk = trie_side_table_load_chunk(top);
	if (!chunk)
		goto out;

	trie_side_table_store_entry(chunk, trie_side_table_slot_index(id), entry);
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
}

int __stack_depot_trie_side_table_store(u32 id, const void *entry)
{
	const void **chunk;
	unsigned long flags;
	unsigned int top;
	int ret = -EINVAL;

	if (!READ_ONCE(trie_side_table_initialized) || !id || !entry)
		return -EINVAL;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	if (id > trie_side_table_next_id)
		goto out;
	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size)
		goto out;

	chunk = trie_side_table_load_chunk(top);
	if (!chunk)
		goto out;

	trie_side_table_store_entry(chunk, trie_side_table_slot_index(id), entry);
	ret = 0;
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return ret;
}

const void *__stack_depot_trie_side_table_lookup(u32 id)
{
	const void **chunk;
	unsigned int top;

	if (!READ_ONCE(trie_side_table_initialized) || !id)
		return NULL;

	top = trie_side_table_top_index(id);
	if (top >= trie_side_table_top_size)
		return NULL;

	chunk = trie_side_table_load_chunk(top);
	if (!chunk)
		return NULL;

	return trie_side_table_load_entry(chunk, trie_side_table_slot_index(id));
}

size_t __stack_depot_trie_side_table_entries(void)
{
	return READ_ONCE(trie_side_table_initialized) ?
		READ_ONCE(trie_side_table_next_id) : 0;
}

size_t __stack_depot_trie_side_table_bytes(void)
{
	unsigned int nr_chunks;
	size_t bytes;
	size_t top_bytes;

	if (!READ_ONCE(trie_side_table_initialized))
		return 0;
	if (check_mul_overflow((size_t)trie_side_table_top_size,
			       sizeof(*trie_side_table_chunks), &top_bytes))
		return SIZE_MAX;

	nr_chunks = READ_ONCE(trie_side_table_nr_chunks);
	if (check_mul_overflow((size_t)nr_chunks,
			       STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE *
			       sizeof(*trie_side_table_chunks[0]), &bytes))
		return SIZE_MAX;
	if (check_add_overflow(top_bytes, bytes, &bytes))
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
		    trie_pool_add_size(req->node_slots[i].size, &total))
			return -EINVAL;
	}
	for (i = 0; i < req->nr_child_slots; i++) {
		if (req->child_slots[i].array ||
		    trie_pool_add_size(req->child_slots[i].size, &total))
			return -EINVAL;
	}
	if (trie_pool_add_size(req->storage_size, &total))
		return -EINVAL;

	if (!raw_spin_trylock_irqsave(&pool_lock, flags))
		return -EBUSY;
	if (!stack_pools) {
		ret = -ENOSPC;
		goto out;
	}
	if (pools_num < 1) {
		req->mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->prealloc)) {
			ret = -ENOSPC;
			goto out;
		}
		req->mark->added_pool = true;
	}
	if (WARN_ON_ONCE(pool_offset > DEPOT_POOL_SIZE))
		goto out;
	if (total > DEPOT_POOL_SIZE - pool_offset) {
		req->mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->prealloc)) {
			ret = -ENOSPC;
			goto out;
		}
		req->mark->added_pool = true;
	}

	req->mark->pool_index = pools_num - 1;
	pool = stack_pools[req->mark->pool_index];
	if (WARN_ON_ONCE(!pool))
		goto out;

	req->mark->offset = pool_offset;
	req->mark->pool = pool;
	req->mark->size = total;
	offset = pool_offset;
	for (i = 0; i < req->nr_node_slots; i++) {
		req->node_slots[i].node = pool + offset;
		offset += __stack_depot_trie_pool_alloc_size(req->node_slots[i].size);
	}
	for (i = 0; i < req->nr_child_slots; i++) {
		req->child_slots[i].array = pool + offset;
		offset += __stack_depot_trie_pool_alloc_size(req->child_slots[i].size);
	}
	*req->storage = pool + offset;
	pool_offset += total;
	ret = 0;
out:
	raw_spin_unlock_irqrestore(&pool_lock, flags);
	return ret;
}

void __stack_depot_trie_alloc_txn_init(struct stack_depot_trie_alloc_txn *txn)
{
	if (txn)
		memset(txn, 0, sizeof(*txn));
}

int
__stack_depot_trie_alloc_txn_id(struct stack_depot_trie_alloc_txn *txn, void **prealloc)
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
		__stack_depot_trie_alloc_txn_rollback(req->txn);
		trie_alloc_request_clear_outputs(req);
		return ret;
	}

	return 0;
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

int
__stack_depot_trie_side_prepare(const struct stack_depot_trie_leaf_update *updates,
				unsigned int nr_updates, void *ctx)
{
	struct stack_depot_trie_side_prepare *state = ctx;
	unsigned int start;
	unsigned int i;
	int ret;

	if (!state || (!updates && nr_updates))
		return -EINVAL;

	start = state->nr_updates;
	for (i = 0; i < nr_updates; i++) {
		if (state->nr_updates >= STACK_DEPOT_TRIE_MAX_LEAF_UPDATES) {
			ret = -EINVAL;
			goto rollback;
		}

		state->updates[state->nr_updates].leaf_id = updates[i].leaf_id;
		state->updates[state->nr_updates].old_leaf =
			__stack_depot_trie_side_table_lookup(updates[i].leaf_id);
		state->nr_updates++;
		ret = __stack_depot_trie_side_table_store(updates[i].leaf_id, updates[i].leaf);
		if (ret)
			goto rollback;
	}

	return 0;

rollback:
	while (state->nr_updates > start) {
		struct stack_depot_trie_side_checkpoint *update;

		state->nr_updates--;
		update = &state->updates[state->nr_updates];
		__stack_depot_trie_side_table_restore(update->leaf_id, update->old_leaf);
	}
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
	stack_table = alloc_large_system_hash("stackdepot",
						sizeof(struct list_head),
						entries,
						STACK_HASH_TABLE_SCALE,
						HASH_EARLY,
						NULL,
						&stack_hash_mask,
						1UL << STACK_BUCKET_NUMBER_ORDER_MIN,
						1UL << STACK_BUCKET_NUMBER_ORDER_MAX);
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

	return 0;
}

/* Allocates a hash table via kvcalloc. Can be used after boot. */
int stack_depot_init(void)
{
	static DEFINE_MUTEX(stack_depot_init_mutex);
	unsigned long entries;
	int ret = 0;

	mutex_lock(&stack_depot_init_mutex);

	if (stack_depot_disabled || stack_table)
		goto out_unlock;

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
		stack_depot_disabled = true;
		ret = -ENOMEM;
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

	if (!new_pool && *prealloc) {
		/* We have preallocated memory, use it. */
		WRITE_ONCE(new_pool, *prealloc);
		*prealloc = NULL;
	}

	if (!new_pool)
		return false; /* new_pool and *prealloc are NULL */

	/* Save reference to the pool to be used by depot_fetch_stack(). */
	stack_pools[pools_num] = new_pool;

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
depot_alloc_stack(unsigned long *entries, unsigned int nr_entries, u32 hash, depot_flags_t flags, void **prealloc)
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
static inline
int stackdepot_memcmp(const unsigned long *u1, const unsigned long *u2,
			unsigned int n)
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

depot_stack_handle_t stack_depot_save_flags(unsigned long *entries,
					    unsigned int nr_entries,
					    gfp_t alloc_flags,
					    depot_flags_t depot_flags)
{
	struct list_head *bucket;
	struct stack_record *found = NULL;
	depot_stack_handle_t handle = 0;
	struct page *page = NULL;
	void *prealloc = NULL;
	bool allow_spin = gfpflags_allow_spinning(alloc_flags);
	bool can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) && allow_spin;
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

	hash = hash_stack(entries, nr_entries);
	bucket = &stack_table[hash & stack_hash_mask];

	/* Fast path: look the stack trace up without locking. */
	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
	if (found)
		goto exit;

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
			goto exit;
	} else {
		raw_spin_lock_irqsave(&pool_lock, flags);
	}
	printk_deferred_enter();

	/* Try to find again, to avoid concurrently inserting duplicates. */
	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
	if (!found) {
		struct stack_record *new =
			depot_alloc_stack(entries, nr_entries, hash, depot_flags, &prealloc);

		if (new) {
			/*
			 * This releases the stack record into the bucket and
			 * makes it visible to readers in find_stack().
			 */
			list_add_rcu(&new->hash_list, bucket);
			found = new;
		}
	}

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
exit:
	if (prealloc) {
		/* Stack depot didn't use this memory, free it. */
		if (!allow_spin)
			free_pages_nolock(virt_to_page(prealloc), DEPOT_POOL_ORDER);
		else
			free_pages((unsigned long)prealloc, DEPOT_POOL_ORDER);
	}
	if (found)
		handle = found->handle.handle;
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
	/* A stale read is harmless: cmpxchg reloads @old before retry checks. */
	old = refcount_read(&stack->count);
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
			WARN_RATELIMIT(1, "stack depot count underflow\n");
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

static int frame_run_read_to_scratch(const struct stack_depot_frame_run *run,
				     const void *src, unsigned long *scratch,
				     unsigned int nr_scratch)
{
	/* Private staging helper: the public frame-run read API rejects aliasing. */
	return stack_depot_frame_run_read_compressed(run, src, scratch, scratch,
						      nr_scratch);
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
	size = sizeof(struct stack_depot_trie_node);
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
		child_size = __stack_depot_trie_child_array_size(node->children->nr_children);
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
		child_size = __stack_depot_trie_child_array_size(1);
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
	array_size = __stack_depot_trie_child_array_size(array->nr_children);
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
			child_size = __stack_depot_trie_child_array_size(children->nr_children);
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

	if (!entries || !nr_entries || !new_storage)
		return -EINVAL;
	if (!entries[0])
		return -EINVAL;
	if ((nr_node_slots && !node_slots) || (nr_child_slots && !child_slots))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_storage,
			__alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;

	slot = trie_publish_slot(root, parent);
	if (!slot)
		return -EINVAL;
	if (stack_depot_ranges_overlap(new_storage, new_storage_size, slot,
				       sizeof(*slot)))
		return -EINVAL;
	if (root) {
		if (trie_node_slot_overlaps(node_slots, nr_node_slots, slot,
					    sizeof(*slot)))
			return -EINVAL;
		if (trie_child_slot_overlaps(child_slots, nr_child_slots, slot,
					     sizeof(*slot)))
			return -EINVAL;
	}
	if (parent && trie_ancestor_overlaps(parent, new_storage, new_storage_size))
		return -EINVAL;
	if (trie_node_slot_overlaps(node_slots, nr_node_slots, new_storage,
				    new_storage_size) ||
	    trie_child_slot_overlaps(child_slots, nr_child_slots, new_storage,
				     new_storage_size))
		return -EINVAL;

	/* Pairs with append publication's smp_store_release(). */
	children = smp_load_acquire(slot);
	size = __stack_depot_trie_child_array_size(children ?
						       children->nr_children + 1 : 1);
	if (!size || new_storage_size < size)
		return -EINVAL;
	if (children) {
		size = __stack_depot_trie_child_array_size(children->nr_children);
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
	size_t size;

	slot = trie_publish_slot(root, parent);
	if (!slot || !new_storage)
		return -EINVAL;
	if ((nr_node_slots && !node_slots) || (nr_child_slots && !child_slots))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_storage,
			__alignof__(struct stack_depot_trie_child_array)))
		return -EINVAL;
	if (stack_depot_ranges_overlap(new_storage, new_storage_size, slot,
				       sizeof(*slot)))
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
	size = __stack_depot_trie_child_array_size(children->nr_children);
	if (!size)
		return -EINVAL;
	if (stack_depot_ranges_overlap(children, size, new_storage,
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
	if (trie_child_array_subtree_overlaps(children, parent, new_storage, new_storage_size))
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

	size = __stack_depot_trie_child_array_size(old_array->nr_children);
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
			    void *new_storage, unsigned int pos)
{
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned int i;

	new_array->nr_children = old_array->nr_children;
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
	if (prepare) {
		if (!prepare->fn)
			return -EINVAL;
		update.leaf_id = leaf_id;
		update.leaf = slot->node;
		ret = prepare->fn(&update, 1, prepare->ctx);
		if (ret)
			return ret;
	}
	trie_child_array_replace_at(old_array, slot->node, new_storage, pos);
	trie_reparent_children(slot->node);

	publish_slot = trie_publish_slot(root, parent);
	/* Publish the fully initialized replacement array last. */
	smp_store_release(publish_slot, new_storage);
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
	struct stack_depot_trie_node *parent = parent_ptr;
	struct stack_depot_trie_child_array *new_array = new_storage;
	size_t storage_size = new_storage_size;
	size_t new_size;
	size_t old_size;

	if ((root && parent) || (!root && !parent) || !head || !new_array)
		return -EINVAL;
	if (head->parent != parent)
		return -EINVAL;

	if (root) {
		if (stack_depot_ranges_overlap(new_array, storage_size,
					       &root->children, sizeof(root->children)))
			return -EINVAL;
		slot = &root->children;
	} else {
		if (trie_ancestor_overlaps(parent, new_array, storage_size))
			return -EINVAL;
		slot = &parent->children;
	}

	old_array = READ_ONCE(*slot);
	old_size = old_array ?
		__stack_depot_trie_child_array_size(old_array->nr_children) : 0;
	new_size = old_array ? old_array->nr_children + 1 : 1;
	new_size = __stack_depot_trie_child_array_size(new_size);
	if (!new_size || storage_size < new_size)
		return -EINVAL;
	if (old_array &&
	    stack_depot_ranges_overlap(old_array, old_size, new_array,
				       storage_size))
		return -EINVAL;
	if (trie_chain_overlaps(head, new_array, storage_size))
		return -EINVAL;
	if (__stack_depot_trie_child_array_insert(old_array, head, new_array, storage_size))
		return -EINVAL;
	if (prepare) {
		struct stack_depot_trie_leaf_update update = {
			.leaf_id = leaf_id,
			.leaf = leaf,
		};
		int ret;

		if (!prepare->fn)
			return -EINVAL;
		if (!leaf_id || !leaf)
			return -EINVAL;
		ret = prepare->fn(&update, 1, prepare->ctx);
		if (ret)
			return ret;
	}

	/* Publish the fully initialized replacement array last. */
	smp_store_release(slot, new_array);
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
	u32 base = parent ? parent->stack_len : 0;

	if (!node || node->parent != parent || !node->stack_len)
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

	for (; node; node = node->parent, depth++) {
		if (depth >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return true;
		if (trie_node_depth_invalid(node->parent, node))
			return true;
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
		__stack_depot_trie_child_array_size(children->nr_children);
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
				__stack_depot_trie_child_array_size(children->nr_children);
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

unsigned int
__stack_depot_trie_fetch_into(const void *leaf, unsigned long *entries,
			      unsigned int max_entries, unsigned long *scratch,
			      unsigned int nr_scratch)
{
	const struct stack_depot_trie_node *node = leaf;
	unsigned int pos;
	unsigned int total;
	int ret;

	if (!node || !entries || !scratch || !node->stack_len || !node->leaf_id)
		return 0;

	total = node->stack_len;
	if (max_entries < total || nr_scratch < total)
		return 0;
	if (stack_depot_ranges_overlap(entries, total * sizeof(*entries), scratch,
				       total * sizeof(*scratch)))
		return 0;

	pos = total;
	for (node = leaf; node; node = trie_load_parent(node)) {
		if (stack_depot_frame_run_validate(&node->run))
			return 0;
		if (node->stack_len != pos || node->run.nr_entries > pos)
			return 0;
		pos -= node->run.nr_entries;
		/* nr_scratch >= total, and pos tracks the remaining prefix length. */
		/* Decode directly into the staged output; node->data is separate. */
		if (node->run.mode == STACK_DEPOT_FRAME_COMPRESSED)
			ret = frame_run_read_to_scratch(&node->run, node->data,
							&scratch[pos], nr_scratch - pos);
		else
			ret = frame_run_read(&node->run, node->data,
					     node->run.bytes, &scratch[pos],
					     nr_scratch - pos, NULL, 0);
		if (ret)
			return 0;
	}
	if (pos)
		return 0;

	memcpy(entries, scratch, total * sizeof(*entries));
	return total;
}

size_t __stack_depot_trie_child_array_size(unsigned int nr_children)
{
	size_t size;
	size_t bytes;

	if (check_mul_overflow((size_t)nr_children,
			       sizeof(struct stack_depot_trie_node *), &bytes))
		return 0;
	size = sizeof(struct stack_depot_trie_child_array);
	if (check_add_overflow(size, bytes, &size))
		return 0;

	return ALIGN(size, sizeof(unsigned long));
}

int __stack_depot_trie_child_array_init(void *storage, size_t storage_size,
					const void * const *children,
					unsigned int nr_children)
{
	struct stack_depot_trie_child_array *array = storage;
	const struct stack_depot_trie_node * const *nodes =
		(const struct stack_depot_trie_node * const *)children;
	unsigned long last = 0;
	unsigned int i;

	if (!array || storage_size < __stack_depot_trie_child_array_size(nr_children))
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)array, __alignof__(*array)))
		return -EINVAL;
	if (nr_children && !nodes)
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
	size = __stack_depot_trie_child_array_size(children->nr_children);
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
	ret = trie_child_array_replace_precheck(old_array, child, new_storage,
						new_storage_size, &pos);
	if (ret)
		return ret;

	ret = trie_split_subtree_prepare(child, matched, leaf_id, entries,
					 nr_entries, node_slots, nr_node_slots,
					 child_slots, nr_child_slots, scratch,
					 nr_scratch, prepare, &prefix,
					 tail, &used);
	if (ret)
		return ret;

	trie_child_array_replace_at(old_array, prefix, new_storage, pos);
	/* Publish the fully initialized replacement array last. */
	smp_store_release(publish_slot, new_storage);
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

	right = array->nr_children;
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
	old_size = __stack_depot_trie_child_array_size(nr_old);
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
	unsigned long *stack_entries;
	unsigned int nr_entries;
	unsigned int copied = 0;

	if (!handle || !entries || !max_entries)
		return 0;

	/* Extend the lookup RCU section so the fetched record cannot be reused. */
	rcu_read_lock_sched_notrace();
	nr_entries = stack_depot_fetch(handle, &stack_entries);
	if (!nr_entries || nr_entries > max_entries)
		goto out;

	/*
	 * stack_depot_fetch() returns stackdepot-owned storage; the caller must
	 * keep the handle valid while this helper copies from it.
	 */
	memcpy(entries, stack_entries, nr_entries * sizeof(*entries));
	copied = nr_entries;

out:
	rcu_read_unlock_sched_notrace();
	return copied;
}
EXPORT_SYMBOL_GPL(stack_depot_fetch_into);

void stack_depot_put(depot_stack_handle_t handle)
{
	struct stack_record *stack;

	if (!handle || stack_depot_disabled)
		return;

	stack = depot_fetch_stack(handle);
	/*
	 * Should always be able to find the stack record, otherwise this is an
	 * unbalanced put attempt (or corrupt handle).
	 */
	if (WARN(!stack, "corrupt handle or unbalanced stack_depot_put()"))
		return;

	if (refcount_dec_and_test(&stack->count))
		depot_free_stack(stack);
}
EXPORT_SYMBOL_GPL(stack_depot_put);

void stack_depot_print(depot_stack_handle_t stack)
{
	unsigned long *entries;
	unsigned int nr_entries;

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

	nr_entries = stack_depot_fetch(handle, &entries);
	return nr_entries ? stack_trace_snprint(buf, size, entries, nr_entries,
						spaces) : 0;
}
EXPORT_SYMBOL_GPL(stack_depot_snprint);

depot_stack_handle_t __must_check stack_depot_set_extra_bits(
			depot_stack_handle_t handle, unsigned int extra_bits)
{
	union handle_parts parts = { .handle = handle };

	/* Don't set extra bits on empty handles. */
	if (!handle)
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
	for (int i = 0; i < DEPOT_COUNTER_COUNT; i++)
		seq_printf(seq, "%s: %ld\n", counter_names[i], data_race(counters[i]));

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
