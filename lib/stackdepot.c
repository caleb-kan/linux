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
		u32 offset				: DEPOT_OFFSET_BITS;
		u32 extra				: STACK_DEPOT_EXTRA_BITS;
	};
};

struct stack_record {
	struct list_head hash_list;	/* Links in the hash table */
	u32 hash;					/* Hash in hash table */
	u32 size;					/* Number of stored frames */
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
	u32 leaf_id;
	u32 stack_len;
	struct stack_depot_frame_run run;
	unsigned char data[];
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
	/* Saturated records are persistent but not in counted mode. */
	if (raw > INT_MAX)
		return false;

	*count = raw;
	return true;
}

void __stack_depot_set_count(depot_stack_handle_t handle, unsigned int count)
{
	struct stack_record *stack;

	/* Reject values outside positive refcount space. */
	if (!handle || !count || count >= INT_MAX)
		return;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return;

	refcount_set(&stack->count, (int)count);
}

bool __stack_depot_inc_count(depot_stack_handle_t handle, unsigned int count)
{
	struct stack_record *stack;
	int new;
	int old = REFCOUNT_SATURATED;
	bool was_saturated = false;

	if (!handle || !count || count >= (unsigned int)INT_MAX - 1)
		return false;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return false;

	new = 1 + (int)count;
	/*
	 * Intentional refcount_t internals use: no helper conditionally
	 * converts the persistent REFCOUNT_SATURATED sentinel to a positive
	 * page_owner count. The cmpxchg only performs that one-way transition;
	 * normal counted records continue through refcount_add().
	 */
	if (atomic_try_cmpxchg_relaxed(&stack->count.refs, &old, new))
		was_saturated = true;
	else
		/* Preserve refcount_add() overflow warning and saturation semantics. */
		refcount_add((int)count, &stack->count);

	return was_saturated;
}

bool __stack_depot_dec_count_and_test(depot_stack_handle_t handle,
				      unsigned int count)
{
	struct stack_record *stack;
	int new;
	int old;

	if (!handle || !count || count >= (unsigned int)INT_MAX - 1)
		return false;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return false;

	/*
	 * Intentional refcount_t internals use: refcount_sub_and_test() would
	 * saturate on underflow, but page_owner accounting must warn and leave
	 * the existing count unchanged.
	 */
	old = refcount_read(&stack->count);
	do {
		/* Retry checks use the current count as the linearization point. */
		/* Saturated counts are negative and intentionally fail closed here. */
		if (old <= 0)
			return false;
		if (WARN_RATELIMIT(count > (unsigned int)old,
				   "stack depot count underflow\n"))
			return false;

		new = old - (int)count;
	} while (!atomic_try_cmpxchg_release(&stack->count.refs, &old, new));

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
	return stack_depot_frame_run_read_compressed(run, src, scratch, scratch,
						      nr_scratch);
}

static bool stack_depot_ranges_overlap(const void *a, const void *b, size_t size)
{
	unsigned long a_start = (unsigned long)a;
	unsigned long b_start = (unsigned long)b;
	unsigned long a_end;
	unsigned long b_end;

	if (!size)
		return false;
	if (check_add_overflow(a_start, size, &a_end) ||
	    check_add_overflow(b_start, size, &b_end))
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

	if (run->mode == STACK_DEPOT_FRAME_RAW) {
		memcpy(entries, src, run->bytes);
		return 0;
	}
	if (!scratch || nr_scratch < run->nr_entries)
		return -EINVAL;
	if (stack_depot_ranges_overlap(entries, scratch,
				       run->nr_entries * sizeof(*entries)))
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
		    parent_node->stack_len > U32_MAX - run.nr_entries)
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
	node->leaf_id = leaf_id;
	node->stack_len = stack_len;
	node->run = run;
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

	pos = total;
	for (node = leaf; node; node = node->parent) {
		if (node->stack_len != pos || node->run.nr_entries > pos)
			return 0;
		pos -= node->run.nr_entries;
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

	/* Follow stackdepot's non-traceable RCU read-side convention while copying. */
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
