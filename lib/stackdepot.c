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
	if (node->run.mode == STACK_DEPOT_FRAME_RAW &&
	    !memcmp(node->data, entries, limit * sizeof(*entries)))
		return limit;

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
	for (; node; node = node->parent) {
		size_t child_size;
		size_t node_size;

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

int
__stack_depot_trie_publish_append(struct stack_depot_trie_root *root,
				  void *parent_ptr, const void *head_ptr,
				  void *new_storage, size_t new_storage_size)
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

	/* Publish the fully initialized replacement array last. */
	smp_store_release(slot, new_array);
	return 0;
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

int __stack_depot_trie_insert_append(struct stack_depot_trie_root *root,
				     void *parent_ptr, u32 leaf_id,
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
	const void *head;
	const void *last;
	unsigned int used;
	struct stack_depot_trie_node *parent = parent_ptr;
	int ret;

	if (!leaf_id || !tail || !nr_used)
		return -EINVAL;

	for (;;) {
		struct stack_depot_trie_lookup lookup;

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
	ret = __stack_depot_trie_publish_append(root, parent, head, new_storage,
						new_storage_size);
	if (ret)
		return ret;

	*tail = last;
	*nr_used = used;
	return 0;
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
	for (node = leaf; node; node = node->parent) {
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
