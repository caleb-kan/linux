// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack depot - a stack trace storage that avoids duplication.
 *
 * Internally, stack depot has two storage backends. Refcounted entries and
 * callers that request STACK_DEPOT_FLAG_COUNTABLE use the legacy hash table with
 * contiguous stack records in stack pools. Persistent non-refcounted entries
 * can use trie storage when enabled; trie nodes share common frame prefixes and
 * are published through RCU/COW child arrays.
 *
 * Author: Alexander Potapenko <glider@google.com>
 * Copyright (C) 2016 Google, Inc.
 *
 * Based on the code by Dmitry Chernenkov.
 */

#define pr_fmt(fmt) "stackdepot: " fmt

#include <linux/bitmap.h>
#include <linux/build_bug.h>
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
#include <linux/spinlock.h>
#include <linux/stacktrace.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/kasan-enabled.h>

#include <asm/stackdepot.h>

enum stack_depot_frame_mode {
	STACK_DEPOT_FRAME_RAW,
	STACK_DEPOT_FRAME_COMPRESSED,
};

enum stack_depot_trie_lookup_status {
	STACK_DEPOT_TRIE_LOOKUP_APPEND,
	STACK_DEPOT_TRIE_LOOKUP_DESCEND,
	STACK_DEPOT_TRIE_LOOKUP_FOUND,
	STACK_DEPOT_TRIE_LOOKUP_PROMOTE,
	STACK_DEPOT_TRIE_LOOKUP_SPLIT,
};

/*
 * A trie node stores one run of frames that all use the same payload format.
 * Architectures may compress some frames to 32-bit payloads; mixed raw and
 * compressed input is split across multiple trie nodes so each node has one
 * decoding mode.
 */
struct stack_depot_frame_run {
	u16 nr_entries;
	u8 mode;
};

static_assert(CONFIG_STACKDEPOT_MAX_FRAMES <= U16_MAX);

struct stack_depot_trie_node;
struct stack_depot_trie_child_array;
struct stack_depot_trie_side_dir;
struct stack_depot_trie_side_entry;

struct stack_depot_trie_node_slot {
	struct stack_depot_trie_node *node;
	size_t size;
};

struct stack_depot_trie_child_array_slot {
	struct stack_depot_trie_child_array *array;
	size_t size;
};

struct stack_depot_trie_root {
	const struct stack_depot_trie_child_array *children;
};

struct stack_depot_trie_lookup {
	const struct stack_depot_trie_child_array *children;
	const struct stack_depot_trie_node *node;
	enum stack_depot_trie_lookup_status status;
	unsigned int matched;
	unsigned int pos;
};

struct stack_depot_trie_leaf_update {
	u32 leaf_id;
	const struct stack_depot_trie_node *leaf;
};

/* A split can repoint the old leaf and publish one new leaf. */
#define STACK_DEPOT_TRIE_MAX_LEAF_UPDATES 2
#define STACK_DEPOT_TRIE_MAX_NODE_SLOTS (CONFIG_STACKDEPOT_MAX_FRAMES + 1)
#define STACK_DEPOT_TRIE_MAX_CHILD_SLOTS CONFIG_STACKDEPOT_MAX_FRAMES

struct stack_depot_trie_side_prealloc {
	/* Preallocated side-table directory page for sparse growth. */
	struct stack_depot_trie_side_dir *dir;
	/* Preallocated side-table leaf chunk for sparse growth. */
	struct stack_depot_trie_side_entry *chunk;
};

struct stack_depot_trie_pool_mark {
	/* Stackdepot pool backing this transactional reservation. */
	void *pool;
	size_t prev_offset;
	size_t offset;
	size_t size;
	unsigned int pool_index;
	bool added_pool;
};

struct stack_depot_trie_alloc_txn {
	struct stack_depot_trie_pool_mark pool;
	u32 leaf_id;
};

struct stack_depot_trie_alloc_request {
	struct stack_depot_trie_alloc_txn *txn;
	struct stack_depot_trie_node_slot *node_slots;
	struct stack_depot_trie_child_array_slot *child_slots;
	/* Optional replacement child-array storage. */
	struct stack_depot_trie_child_array **storage;
	/* Optional fresh stackdepot pool page, preallocated before insertion. */
	void **pool_prealloc;
	struct stack_depot_trie_side_prealloc *side_prealloc;
	size_t storage_size;
	unsigned int nr_node_slots;
	unsigned int nr_child_slots;
};

struct stack_depot_trie_alloc_workspace {
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_alloc_request req;
	struct stack_depot_trie_node_slot node_slots[STACK_DEPOT_TRIE_MAX_NODE_SLOTS];
	struct stack_depot_trie_child_array_slot child_slots[STACK_DEPOT_TRIE_MAX_CHILD_SLOTS];
	u32 scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	struct stack_depot_trie_child_array *storage;
};

#define STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS 9
#define STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE \
	(1U << STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS)

static bool __stack_depot_trie_ready(void);
static depot_stack_handle_t __stack_depot_trie_handle(u32 leaf_id);
static u32 __stack_depot_trie_leaf_id(depot_stack_handle_t handle);
static u32 __stack_depot_trie_max_leaf_id(void);
static int __stack_depot_trie_side_table_init(gfp_t gfp_flags);
static int __stack_depot_trie_side_table_prealloc(gfp_t gfp_flags,
						  struct stack_depot_trie_side_prealloc *prealloc);
static void
__stack_depot_trie_side_table_free_prealloc(struct stack_depot_trie_side_prealloc *prealloc);
static u32
__stack_depot_trie_side_table_prepare_id(struct stack_depot_trie_side_prealloc *prealloc);
static void __stack_depot_trie_side_table_commit_id(u32 id);
static const struct stack_depot_trie_node *__stack_depot_trie_side_table_lookup(u32 id);
static size_t __stack_depot_trie_side_table_bytes(void);
static size_t __stack_depot_trie_pool_alloc_size(size_t size);
static void *__stack_depot_trie_pool_prealloc(gfp_t gfp_flags);
static int
__stack_depot_trie_alloc_prealloc(gfp_t alloc_flags,
				  depot_flags_t depot_flags, void **pool_prealloc,
				  struct stack_depot_trie_side_prealloc *side_prealloc);
static int __stack_depot_trie_pool_carve(struct stack_depot_trie_alloc_request *req);
static int
__stack_depot_trie_alloc_txn_plan(const struct stack_depot_trie_root *root,
				  const unsigned long *entries,
				  unsigned int nr_entries,
				  struct stack_depot_trie_node_slot *node_slots,
				  unsigned int nr_node_slots,
				  struct stack_depot_trie_child_array_slot *child_slots,
				  unsigned int nr_child_slots,
				  struct stack_depot_trie_alloc_txn *txn,
				  struct stack_depot_trie_child_array **storage,
				  void **pool_prealloc,
				  struct stack_depot_trie_side_prealloc *side_prealloc,
				  struct stack_depot_trie_alloc_request *req);
static int
__stack_depot_trie_workspace_insert(struct stack_depot_trie_root *root,
				    const unsigned long *entries,
				    unsigned int nr_entries, void **pool_prealloc,
				    struct stack_depot_trie_side_prealloc *side_prealloc,
				    struct stack_depot_trie_alloc_workspace *workspace,
				    u32 *leaf_id);
static int __stack_depot_trie_alloc_txn_reserve(struct stack_depot_trie_alloc_request *req);
static int
__stack_depot_trie_alloc_txn_insert(struct stack_depot_trie_root *root,
				    struct stack_depot_trie_alloc_request *req,
				    const unsigned long *entries, unsigned int nr_entries,
				    u32 *scratch, unsigned int nr_scratch,
				    u32 *leaf_id);
static void __stack_depot_trie_alloc_txn_rollback(struct stack_depot_trie_alloc_txn *txn);
static int trie_side_publish(const struct stack_depot_trie_leaf_update *updates,
			     unsigned int nr_updates);
static int __stack_depot_frame_run_init(const unsigned long *entries,
					unsigned int nr_entries,
					struct stack_depot_frame_run *run);
static size_t __stack_depot_trie_node_size(const struct stack_depot_frame_run *run);
static int __stack_depot_trie_node_init(void *storage, size_t storage_size,
					const struct stack_depot_trie_node *parent,
					u32 leaf_id,
					const unsigned long *entries,
					unsigned int nr_entries, u32 *scratch,
					unsigned int nr_scratch);
static int __stack_depot_trie_node_init_slice(void *storage, size_t storage_size,
					      const struct stack_depot_trie_node *parent,
					      u32 leaf_id,
					      const struct stack_depot_trie_node *src_node,
					      unsigned int start,
					      unsigned int nr_entries);
static const struct stack_depot_trie_node *
trie_load_parent(const struct stack_depot_trie_node *node);
static unsigned int __stack_depot_trie_node_match(const struct stack_depot_trie_node *node,
						  const unsigned long *entries,
						  unsigned int nr_entries);
static int
__stack_depot_trie_append_chain(const struct stack_depot_trie_node *parent,
				u32 leaf_id,
				const unsigned long *entries, unsigned int nr_entries,
				const struct stack_depot_trie_node_slot *node_slots,
				unsigned int nr_node_slots,
				const struct stack_depot_trie_child_array_slot *child_slots,
				unsigned int nr_child_slots, u32 *scratch,
				unsigned int nr_scratch,
				const struct stack_depot_trie_node **head,
				const struct stack_depot_trie_node **tail);
static int
__stack_depot_trie_lookup_step(const struct stack_depot_trie_root *root,
			       const struct stack_depot_trie_node *parent,
			       const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_lookup *lookup);
static const struct stack_depot_trie_node *
__stack_depot_trie_find_leaf(const struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries);
static int
__stack_depot_trie_insert_append_prepare(struct stack_depot_trie_root *root,
					 struct stack_depot_trie_node *parent,
					 u32 leaf_id,
					 const unsigned long *entries, unsigned int nr_entries,
					 const struct stack_depot_trie_node_slot *node_slots,
					 unsigned int nr_node_slots,
					 const struct stack_depot_trie_child_array_slot
					 *child_slots,
					 unsigned int nr_child_slots, u32 *scratch,
					 unsigned int nr_scratch,
					 struct stack_depot_trie_child_array *new_storage,
					 size_t new_storage_size);
static int
__stack_depot_trie_insert_plan(const struct stack_depot_trie_root *root,
			       const struct stack_depot_trie_node *parent,
			       const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_node_slot *node_slots,
			       unsigned int nr_node_slots,
			       struct stack_depot_trie_child_array_slot *child_slots,
			       unsigned int nr_child_slots, size_t *new_storage_size,
			       unsigned int *nr_used, unsigned int *nr_child_used);
static unsigned int __stack_depot_trie_fetch_into(const struct stack_depot_trie_node *leaf,
						  unsigned long *entries,
						  unsigned int max_entries);
static unsigned int __stack_depot_trie_fetch_handle_into(depot_stack_handle_t handle,
							 unsigned long *entries,
							 unsigned int max_entries);
static inline size_t __stack_depot_trie_child_array_size(unsigned int nr_children);
static int __stack_depot_trie_child_array_init(void *storage, size_t storage_size,
					       const struct stack_depot_trie_node * const *children,
					       unsigned int nr_children);
static int
__stack_depot_trie_split_child_array_init(void *storage, size_t storage_size,
					  const struct stack_depot_trie_node *old_tail,
					  const struct stack_depot_trie_node *new_head);
static int
__stack_depot_trie_child_array_insert(const struct stack_depot_trie_child_array *old,
				      const struct stack_depot_trie_node *child,
				      struct stack_depot_trie_child_array *new_storage,
				      size_t new_storage_size);

/*
 * The pool_index is offset by 1 so the first record does not have a 0 handle.
 */
/* Parsed before mm_core_init(); trie handle decoding assumes this is then fixed. */
static unsigned int stack_max_pools __read_mostly =
	MIN((1LL << DEPOT_POOL_INDEX_BITS) - 1, 8192);

static bool stack_depot_disabled;
static bool __stack_depot_early_init_requested __initdata =
	IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
static bool __stack_depot_early_init_passed __initdata;
static DEFINE_STATIC_KEY_FALSE(stack_depot_trie_enabled);
static DEFINE_MUTEX(stack_depot_init_mutex);
static struct stack_depot_trie_root stack_depot_trie_root;
static struct stack_depot_trie_alloc_workspace __rcu *stack_depot_trie_workspace;
static DEFINE_RAW_SPINLOCK(stack_depot_trie_workspace_lock);
static bool stack_depot_trie_enabled_param;

static bool __stack_depot_trie_enabled(void)
{
	return static_branch_unlikely(&stack_depot_trie_enabled);
}

static void stack_depot_trie_enable(void)
{
	if (__stack_depot_trie_enabled())
		return;

	static_branch_enable(&stack_depot_trie_enabled);
}

module_param_named(trie_enabled, stack_depot_trie_enabled_param, bool, 0);
MODULE_PARM_DESC(trie_enabled, "Enable stack depot trie storage at boot");

/* Use one hash table bucket per 16 KB of memory. */
#define STACK_HASH_TABLE_SCALE 14
/* Limit the number of buckets between 4K and 1M. */
#define STACK_BUCKET_NUMBER_ORDER_MIN 12
#define STACK_BUCKET_NUMBER_ORDER_MAX 20
/* Initial seed for jhash2. */
#define STACK_HASH_SEED 0x9747b28c
#define DEPOT_POOL_INDEX_MASK ((1U << DEPOT_POOL_INDEX_BITS) - 1)
#define DEPOT_OFFSET_MASK ((1U << DEPOT_OFFSET_BITS) - 1)

struct stack_depot_trie_node {
	/* Parent links let fetch rebuild a full stack from a leaf to the root. */
	const struct stack_depot_trie_node *parent;
	/* Child arrays are separate RCU/COW generations. */
	const struct stack_depot_trie_child_array *children;
	u32 leaf_id;
	struct stack_depot_frame_run run;
	unsigned char data[];
};

/*
 * Children are sorted by first frame and searched with lower_bound().
 * Writers may append to spare capacity at the sorted tail, but never change
 * existing child pointers. Other updates build and publish a replacement array.
 */
struct stack_depot_trie_child_array {
	unsigned int nr_children;
	unsigned int capacity;
	const struct stack_depot_trie_node *children[];
};

/* Headerless reusable storage for trie nodes. */
struct stack_depot_trie_free_node {
	struct list_head list;
	size_t size;
};

/*
 * Reusable object storage for child arrays and other payloads that need an
 * object header. A retired child array can carry the old child node that was
 * replaced with it; both become reusable after the array's RCU grace period.
 */
struct stack_depot_trie_free_object {
	struct list_head list;
	unsigned long rcu_state;
	size_t size;
	struct stack_depot_trie_node *pending_node;
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
/* Newly allocated pool that is not yet added to stack_pools. */
static void *new_pool;
/* Number of pools in stack_pools. */
static int pools_num;
/* Offset to the unused space in the currently used pool. */
static size_t pool_offset = DEPOT_POOL_SIZE;
/* Freelist of stack records within stack_pools. */
static LIST_HEAD(free_stacks);

/* Size classes bucket reusable trie storage by aligned allocation size. */
#define STACK_DEPOT_TRIE_FREE_CLASSES \
	((DEPOT_POOL_SIZE >> DEPOT_STACK_ALIGN) + 1)

/*
 * Trie storage is suballocated from stackdepot pools, not slab caches, so pool
 * pressure stays visible through stack_depot_max_pools and no-spin callers can
 * fail without allocator recursion. Trie COW insertion retires child arrays
 * and sometimes the node they replaced. Objects carry the RCU cookie for
 * child-array payloads; headerless node fragments either live directly on
 * free_trie_nodes or are attached to a pending object until that object's grace
 * period has elapsed.
 */
static struct list_head free_trie_objects[STACK_DEPOT_TRIE_FREE_CLASSES];
static struct list_head pending_trie_objects[STACK_DEPOT_TRIE_FREE_CLASSES];
static struct list_head free_trie_nodes[STACK_DEPOT_TRIE_FREE_CLASSES];
static DECLARE_BITMAP(free_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES);
static DECLARE_BITMAP(pending_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES);
static DECLARE_BITMAP(free_trie_node_map, STACK_DEPOT_TRIE_FREE_CLASSES);
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
	[DEPOT_COUNTER_PERSIST_COUNT]	= "hash_persistent_count",
	[DEPOT_COUNTER_PERSIST_BYTES]	= "hash_persistent_bytes",
};

static_assert(ARRAY_SIZE(counter_names) == DEPOT_COUNTER_COUNT);

static bool depot_init_pool(void **prealloc);
static void depot_try_keep_new_pool(void **prealloc);
static u32 trie_side_table_max_id;

/*
 * Hash handles use pool_index_plus_1 <= stack_max_pools. Trie handles use
 * pool_index_plus_1 > stack_max_pools and reinterpret the remaining handle
 * bits as a dense leaf_id, which the side table maps to a trie leaf.
 */
static u32 __stack_depot_trie_max_leaf_id(void)
{
	u64 max_id;

	if (stack_max_pools >= DEPOT_POOL_INDEX_MASK - 1)
		return 0;

	max_id = (u64)(DEPOT_POOL_INDEX_MASK - stack_max_pools - 1) <<
		 DEPOT_OFFSET_BITS;
	return min_t(u64, max_id, U32_MAX);
}

static depot_stack_handle_t __stack_depot_trie_handle(u32 leaf_id)
{
	union handle_parts parts = {};
	u64 pool_index_plus_1;
	u32 pool_delta;
	u32 index;

	if (!leaf_id || leaf_id > READ_ONCE(trie_side_table_max_id))
		return 0;

	index = leaf_id - 1;
	pool_delta = index >> DEPOT_OFFSET_BITS;
	pool_index_plus_1 = (u64)stack_max_pools + 1 + pool_delta;
	if (pool_index_plus_1 >= DEPOT_POOL_INDEX_MASK)
		return 0;

	parts.pool_index_plus_1 = pool_index_plus_1;
	parts.offset = index & DEPOT_OFFSET_MASK;
	return parts.handle;
}

static u32 __stack_depot_trie_leaf_id(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };
	u64 leaf_id;
	u32 pool_delta;

	parts.extra = 0;
	if (parts.pool_index_plus_1 <= stack_max_pools)
		return 0;

	pool_delta = parts.pool_index_plus_1 - stack_max_pools - 1;
	if ((u64)pool_delta + stack_max_pools + 1 >= DEPOT_POOL_INDEX_MASK)
		return 0;

	leaf_id = ((u64)pool_delta << DEPOT_OFFSET_BITS) + parts.offset + 1;
	if (leaf_id > READ_ONCE(trie_side_table_max_id))
		return 0;

	return leaf_id > U32_MAX ? 0 : leaf_id;
}

struct stack_depot_trie_side_entry {
	const struct stack_depot_trie_node __rcu *leaf;
};

/*
 * Trie handles encode a dense leaf ID. The side table maps that ID to a leaf
 * pointer for lockless fetch/print paths, which can run from diagnostic
 * contexts where taking trie_side_table_lock would be unsafe. Init installs the
 * root and first chunk only; additional directories/chunks are preallocated and
 * published lazily as leaf IDs grow. RCU pointer publication makes fully
 * initialized dirs, chunks, and leaves visible to those lockless readers.
 */
#define STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS 9
#define STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE \
	(1U << STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS)

struct stack_depot_trie_side_dir {
	struct stack_depot_trie_side_entry __rcu *chunks[STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE];
};

struct stack_depot_trie_side_root {
	unsigned int dir_capacity;
	struct stack_depot_trie_side_dir __rcu *dirs[];
};

static struct stack_depot_trie_side_root __rcu *trie_side_table_root;
static DEFINE_RAW_SPINLOCK(trie_side_table_lock);
static unsigned int trie_side_table_nr_dirs;
static unsigned int trie_side_table_nr_chunks;
static u32 trie_side_table_next_id;

/* Lock order: workspace_lock -> pool_lock -> trie_side_table_lock. */

static struct stack_depot_trie_alloc_workspace *stack_depot_trie_load_workspace(void)
{
	/* Installed once and never freed; acquire the init-time publication. */
	return rcu_dereference_check(stack_depot_trie_workspace, true);
}

static struct stack_depot_trie_side_root *trie_side_table_load_root(void)
{
	/* Installed once and never freed; acquire the init-time publication. */
	return rcu_dereference_check(trie_side_table_root, true);
}

static bool trie_side_table_is_initialized(void)
{
	return !!trie_side_table_load_root();
}

static bool __stack_depot_trie_ready(void)
{
	return __stack_depot_trie_enabled() &&
		stack_depot_trie_load_workspace() &&
		trie_side_table_is_initialized();
}

static inline unsigned int trie_side_table_top_index(u32 id)
{
	return (id - 1) >> STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS;
}

static inline unsigned int trie_side_table_root_index(u32 id)
{
	return trie_side_table_top_index(id) >> STACK_DEPOT_TRIE_SIDE_TABLE_DIR_BITS;
}

static inline unsigned int trie_side_table_dir_index(u32 id)
{
	return trie_side_table_top_index(id) &
		(STACK_DEPOT_TRIE_SIDE_TABLE_DIR_SIZE - 1);
}

static inline unsigned int trie_side_table_slot_index(u32 id)
{
	return (id - 1) & (STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE - 1);
}

static struct stack_depot_trie_side_dir *trie_side_table_load_dir(unsigned int root)
{
	struct stack_depot_trie_side_root *root_vec;

	root_vec = trie_side_table_load_root();
	if (!root_vec || root >= root_vec->dir_capacity)
		return NULL;
	/* Pairs with trie_side_table_publish_dir(); lookup is lockless. */
	return rcu_dereference_check(root_vec->dirs[root],
				     lockdep_is_held(&trie_side_table_lock) ||
				     rcu_read_lock_sched_held());
}

static void trie_side_table_publish_dir(unsigned int root,
					struct stack_depot_trie_side_dir *dir)
{
	struct stack_depot_trie_side_root *root_vec;

	root_vec = trie_side_table_load_root();
	if (!root_vec || root >= root_vec->dir_capacity)
		return;
	/* Publish the zeroed directory before readers can load it locklessly. */
	rcu_assign_pointer(root_vec->dirs[root], dir);
}

static struct stack_depot_trie_side_entry *
trie_side_table_dir_load_chunk(struct stack_depot_trie_side_dir *dir,
			       unsigned int idx)
{
	/* Pairs with the chunk rcu_assign_pointer() in leaf ID preparation. */
	return rcu_dereference_check(dir->chunks[idx],
				     lockdep_is_held(&trie_side_table_lock) ||
				     rcu_read_lock_sched_held());
}

static u32
__stack_depot_trie_side_table_prepare_id(struct stack_depot_trie_side_prealloc *prealloc)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	struct stack_depot_trie_side_root *root_vec;
	unsigned long flags;
	unsigned int root;
	unsigned int idx;
	u32 id = 0;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	/* Prepare the next slot without making the ID visible for reuse yet. */
	root_vec = trie_side_table_load_root();
	/* Failed or disabled trie init means no leaf IDs can be allocated. */
	if (!root_vec)
		goto out;
	if (!prealloc)
		goto out;

	id = trie_side_table_next_id + 1;
	/* ID zero wraps the 32-bit counter; max_id is trie handle capacity. */
	if (!id || id > trie_side_table_max_id)
		goto out_clear_id;

	root = trie_side_table_root_index(id);
	/* Should be impossible when trie_side_table_max_id and capacity agree. */
	if (root >= root_vec->dir_capacity)
		goto out_clear_id;

	dir = trie_side_table_load_dir(root);
	if (!dir) {
		/* Sparse growth preallocation can lose a race to another writer. */
		if (!prealloc->dir)
			goto out_clear_id;
		dir = prealloc->dir;
		prealloc->dir = NULL;
		trie_side_table_publish_dir(root, dir);
		trie_side_table_nr_dirs++;
	}

	idx = trie_side_table_dir_index(id);
	chunk = trie_side_table_dir_load_chunk(dir, idx);
	if (!chunk) {
		/* Sparse growth preallocation can lose a race to another writer. */
		if (!prealloc->chunk)
			goto out_clear_id;
		chunk = prealloc->chunk;
		prealloc->chunk = NULL;
		rcu_assign_pointer(dir->chunks[idx], chunk);
		trie_side_table_nr_chunks++;
	}

	goto out;

out_clear_id:
	id = 0;
out:
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
	return id;
}

static void __stack_depot_trie_side_table_commit_id(u32 id)
{
	unsigned long flags;
	u32 next;

	if (!trie_side_table_is_initialized() || !id)
		return;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	next = trie_side_table_next_id;
	if (!WARN_ON_ONCE(id != next + 1))
		WRITE_ONCE(trie_side_table_next_id, id);
	raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
}

static size_t trie_side_table_root_bytes(unsigned int root_size)
{
	size_t bytes;

	bytes = struct_size_t(struct stack_depot_trie_side_root, dirs, root_size);
	if (bytes == SIZE_MAX)
		return 0;
	return PAGE_ALIGN(bytes);
}

static inline size_t trie_side_table_dir_bytes(void)
{
	return PAGE_ALIGN(sizeof(struct stack_depot_trie_side_dir));
}

static inline unsigned int trie_side_table_dir_order(void)
{
	return get_order(trie_side_table_dir_bytes());
}

static inline size_t trie_side_table_chunk_bytes(void)
{
	return PAGE_ALIGN(STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE *
			  sizeof(struct stack_depot_trie_side_entry));
}

static inline unsigned int trie_side_table_chunk_order(void)
{
	return get_order(trie_side_table_chunk_bytes());
}

static void trie_side_table_free_dir(struct stack_depot_trie_side_dir *dir)
{
	if (dir)
		free_pages((unsigned long)dir, trie_side_table_dir_order());
}

static int
trie_side_table_install(struct stack_depot_trie_side_root *root_vec,
			unsigned int root_size, u32 max_id,
			struct stack_depot_trie_side_dir *first_dir,
			struct stack_depot_trie_side_entry *first_chunk)
{
	/*
	 * Early init installs the first directory and chunk so early leaf ID
	 * allocation cannot fail immediately. Runtime init installs only the root
	 * vector; sparse directories and chunks are preallocated outside
	 * trie_side_table_lock and published lazily as IDs grow.
	 */
	if (trie_side_table_is_initialized())
		return 0;
	if (!root_vec || !root_size || !max_id)
		return -EINVAL;

	root_vec->dir_capacity = root_size;
	WRITE_ONCE(trie_side_table_nr_dirs, 0);
	WRITE_ONCE(trie_side_table_nr_chunks, 0);
	WRITE_ONCE(trie_side_table_max_id, max_id);
	WRITE_ONCE(trie_side_table_next_id, 0);
	if (first_dir) {
		RCU_INIT_POINTER(root_vec->dirs[0], first_dir);
		WRITE_ONCE(trie_side_table_nr_dirs, 1);
	}
	if (first_dir && first_chunk) {
		RCU_INIT_POINTER(first_dir->chunks[0], first_chunk);
		WRITE_ONCE(trie_side_table_nr_chunks, 1);
	}
	rcu_assign_pointer(trie_side_table_root, root_vec);
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
	struct stack_depot_trie_side_root *root_vec;
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

	root_vec = memblock_alloc(root_bytes, PAGE_SIZE);
	if (!root_vec)
		return -ENOMEM;
	memset(root_vec, 0, root_bytes);
	first_dir = memblock_alloc(dir_bytes, PAGE_SIZE);
	if (!first_dir) {
		memblock_free(root_vec, root_bytes);
		return -ENOMEM;
	}
	memset(first_dir, 0, dir_bytes);
	first_chunk = memblock_alloc(chunk_bytes, PAGE_SIZE);
	if (!first_chunk) {
		memblock_free(first_dir, dir_bytes);
		memblock_free(root_vec, root_bytes);
		return -ENOMEM;
	}
	memset(first_chunk, 0, chunk_bytes);

	return trie_side_table_install(root_vec, root_size, max_leaf_id, first_dir,
				       first_chunk);
}

static int
stack_depot_trie_install_workspace(struct stack_depot_trie_alloc_workspace *workspace)
{
	if (stack_depot_trie_load_workspace())
		return 0;
	if (!workspace)
		return -EINVAL;

	rcu_assign_pointer(stack_depot_trie_workspace, workspace);
	return 0;
}

static int __init stack_depot_trie_init_workspace_memblock(void)
{
	struct stack_depot_trie_alloc_workspace *workspace;
	size_t size;

	if (stack_depot_trie_load_workspace())
		return 0;

	size = sizeof(*stack_depot_trie_workspace);
	workspace = memblock_alloc(size, __alignof__(*workspace));
	if (!workspace)
		return -ENOMEM;
	memset(workspace, 0, size);

	return stack_depot_trie_install_workspace(workspace);
}

static int stack_depot_trie_init_workspace(gfp_t gfp_flags)
{
	struct stack_depot_trie_alloc_workspace *workspace;

	if (stack_depot_trie_load_workspace())
		return 0;

	workspace = kvzalloc(sizeof(*stack_depot_trie_workspace), gfp_flags);
	if (!workspace)
		return -ENOMEM;

	return stack_depot_trie_install_workspace(workspace);
}

static void trie_free_object_buckets_init(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(free_trie_objects); i++) {
		INIT_LIST_HEAD(&free_trie_objects[i]);
		INIT_LIST_HEAD(&pending_trie_objects[i]);
		INIT_LIST_HEAD(&free_trie_nodes[i]);
	}
}

static int __init stack_depot_trie_init_memblock(void)
{
	int ret;

	if (__stack_depot_trie_enabled())
		return 0;

	ret = stack_depot_trie_init_workspace_memblock();
	if (ret)
		return ret;
	ret = __stack_depot_trie_side_table_init_memblock();
	if (ret)
		return ret;

	trie_free_object_buckets_init();
	stack_depot_trie_enable();
	return 0;
}

static int stack_depot_trie_init(gfp_t gfp_flags)
{
	int ret;

	if (__stack_depot_trie_enabled())
		return 0;

	ret = stack_depot_trie_init_workspace(gfp_flags);
	if (ret)
		return ret;
	ret = __stack_depot_trie_side_table_init(gfp_flags);
	if (ret)
		return ret;

	trie_free_object_buckets_init();
	stack_depot_trie_enable();
	return 0;
}

static const struct stack_depot_trie_node *
trie_side_table_load_leaf(struct stack_depot_trie_side_entry *chunk,
			  unsigned int slot)
{
	/* Pairs with side-table leaf rcu_assign_pointer(). */
	return rcu_dereference_check(chunk[slot].leaf,
				     lockdep_is_held(&trie_side_table_lock) ||
				     rcu_read_lock_sched_held());
}

static int __stack_depot_trie_side_table_init(gfp_t gfp_flags)
{
	struct stack_depot_trie_side_root *root_vec;
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
	root_vec = kvzalloc(root_bytes, gfp_flags);
	if (!root_vec)
		return -ENOMEM;

	return trie_side_table_install(root_vec, root_size, max_leaf_id, NULL, NULL);
}

static void *trie_side_table_alloc_page(gfp_t gfp_flags, unsigned int order)
{
	struct page *page;

	page = alloc_pages(gfp_nested_mask(gfp_flags) | __GFP_ZERO,
			   order);
	return page ? page_address(page) : NULL;
}

static int
__stack_depot_trie_side_table_prealloc(gfp_t gfp_flags,
				       struct stack_depot_trie_side_prealloc *prealloc)
{
	struct stack_depot_trie_side_dir *dir;
	struct stack_depot_trie_side_root *root_vec;
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
	root_vec = trie_side_table_load_root();
	if (!root_vec) {
		raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
		return 0;
	}
	id = READ_ONCE(trie_side_table_next_id) + 1;
	if (!id || id > READ_ONCE(trie_side_table_max_id)) {
		raw_spin_unlock_irqrestore(&trie_side_table_lock, flags);
		return 0;
	}
	root = trie_side_table_root_index(id);
	if (root >= root_vec->dir_capacity) {
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

static void
__stack_depot_trie_side_table_free_prealloc(struct stack_depot_trie_side_prealloc *prealloc)
{
	if (!prealloc)
		return;
	trie_side_table_free_dir(prealloc->dir);
	if (prealloc->chunk)
		free_pages((unsigned long)prealloc->chunk,
			   trie_side_table_chunk_order());
	prealloc->dir = NULL;
	prealloc->chunk = NULL;
}

static struct stack_depot_trie_side_entry *
trie_side_table_chunk_locked(u32 id, unsigned int *slot)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	struct stack_depot_trie_side_root *root_vec;
	u32 next_id;
	unsigned int root;

	lockdep_assert_held(&trie_side_table_lock);

	root_vec = trie_side_table_load_root();
	if (!root_vec || !id)
		return NULL;
	next_id = trie_side_table_next_id;
	if (id > next_id + 1)
		return NULL;

	root = trie_side_table_root_index(id);
	if (root >= root_vec->dir_capacity)
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

static const struct stack_depot_trie_node *__stack_depot_trie_side_table_lookup(u32 id)
{
	struct stack_depot_trie_side_entry *chunk;
	struct stack_depot_trie_side_dir *dir;
	unsigned int root;

	if (!id)
		return NULL;

	root = trie_side_table_root_index(id);
	dir = trie_side_table_load_dir(root);
	if (!dir)
		return NULL;
	chunk = trie_side_table_dir_load_chunk(dir, trie_side_table_dir_index(id));
	if (!chunk)
		return NULL;

	return trie_side_table_load_leaf(chunk, trie_side_table_slot_index(id));
}

static size_t __stack_depot_trie_side_table_bytes(void)
{
	struct stack_depot_trie_side_root *root_vec;
	unsigned int nr_dirs;
	unsigned int nr_chunks;
	size_t dir_bytes;
	size_t bytes;
	size_t root_bytes;

	root_vec = trie_side_table_load_root();
	if (!root_vec)
		return 0;
	root_bytes = trie_side_table_root_bytes(root_vec->dir_capacity);
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

static size_t __stack_depot_trie_pool_alloc_size(size_t size)
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

static inline size_t trie_object_header_size(void)
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

static inline struct stack_depot_trie_free_object *trie_object_header(const void *ptr)
{
	return (void *)ptr - trie_object_header_size();
}

static inline void *trie_object_payload(struct stack_depot_trie_free_object *free)
{
	return (void *)free + trie_object_header_size();
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
	free = trie_object_header(ptr);
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
}

static void trie_drain_pending_objects_locked(void)
{
	struct stack_depot_trie_free_object *free;
	struct stack_depot_trie_free_object *tmp;
	unsigned int class;

	lockdep_assert_held(&pool_lock);

	if (bitmap_empty(pending_trie_object_map, STACK_DEPOT_TRIE_FREE_CLASSES))
		return;
	for_each_set_bit(class, pending_trie_object_map,
			 STACK_DEPOT_TRIE_FREE_CLASSES) {
		list_for_each_entry_safe(free, tmp, &pending_trie_objects[class], list) {
			/* Pending lists are FIFO; later entries cannot be ready yet. */
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

static void
trie_retire_object_node_locked(const void *ptr,
			       const struct stack_depot_trie_node *node,
			       size_t node_size)
{
	struct stack_depot_trie_free_object *free;
	size_t size;

	lockdep_assert_held(&pool_lock);
	if (!ptr)
		return;

	free = trie_object_header(ptr);
	free->pending_node = NULL;
	free->pending_node_size = 0;
	size = __stack_depot_trie_pool_alloc_size(node_size);
	if (node && size >= sizeof(struct stack_depot_trie_free_node)) {
		free->pending_node = (struct stack_depot_trie_node *)node;
		free->pending_node_size = size;
	}
	free->rcu_state = get_state_synchronize_rcu();
	trie_free_list_add(&free->list, pending_trie_objects,
			   pending_trie_object_map,
			   trie_free_class(free->size), true);
}

static void trie_retire_object_node(const void *ptr,
				    const struct stack_depot_trie_node *node,
				    size_t node_size)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pool_lock, flags);
	trie_retire_object_node_locked(ptr, node, node_size);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
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

static void *__stack_depot_trie_pool_prealloc(gfp_t gfp_flags)
{
	struct page *page;

	if (!gfpflags_allow_spinning(gfp_flags))
		return NULL;

	page = alloc_pages(gfp_nested_mask(gfp_flags), DEPOT_POOL_ORDER);
	return page ? page_address(page) : NULL;
}

/*
 * Preallocate resources that cannot be allocated while trie writers hold raw
 * spinlocks. Side-table growth is mandatory before a new leaf ID can be
 * reserved, so side-table preallocation failure disables insertion for this
 * save. Pool preallocation is opportunistic: reusable trie storage or active
 * pool space may still satisfy the reservation, and pool_carve() reports
 * -ENOSPC if they do not. Callers without spinning allocation context skip
 * insertion and perform only best-effort lookup.
 */
static int
__stack_depot_trie_alloc_prealloc(gfp_t alloc_flags, depot_flags_t depot_flags,
				  void **pool_prealloc,
				  struct stack_depot_trie_side_prealloc *side_prealloc)
{
	bool can_alloc;
	int ret = 0;

	if (!pool_prealloc || !side_prealloc || *pool_prealloc ||
	    side_prealloc->dir || side_prealloc->chunk)
		return -EINVAL;

	can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) &&
		gfpflags_allow_spinning(alloc_flags);
	if (can_alloc && !READ_ONCE(new_pool))
		*pool_prealloc = __stack_depot_trie_pool_prealloc(alloc_flags);
	if (can_alloc)
		ret = __stack_depot_trie_side_table_prealloc(alloc_flags, side_prealloc);

	if (ret)
		return -ENOSPC;
	return 0;
}

static bool stack_depot_trie_pool_rollback_locked(const struct stack_depot_trie_pool_mark *mark)
{
	size_t end;
	bool ret = false;

	lockdep_assert_held(&pool_lock);

	if (!mark || !mark->size)
		return false;
	if (check_add_overflow(mark->offset, mark->size, &end))
		return false;

	if (mark->pool_index != pools_num - 1 || pool_offset != end)
		return false;
	/*
	 * mark->offset is the reservation start in the active pool. If the
	 * reservation added a new pool, mark->prev_offset is the offset to restore
	 * in the previous pool after making the new pool available for reuse.
	 */
	if (mark->added_pool) {
		if (mark->offset || stack_pools[mark->pool_index] != mark->pool)
			return false;
		if (new_pool && new_pool != STACK_DEPOT_POISON)
			return false;
		stack_pools[mark->pool_index] = NULL;
		WRITE_ONCE(pools_num, mark->pool_index);
		pool_offset = mark->prev_offset;
		WRITE_ONCE(new_pool, mark->pool);
		ret = true;
	} else {
		pool_offset = mark->offset;
		ret = true;
	}

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

static void trie_pool_release_reused_objects_locked(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_mark *mark;
	unsigned long completed;
	unsigned int i;

	lockdep_assert_held(&pool_lock);

	if (!req || !req->txn)
		return;
	mark = &req->txn->pool;
	completed = get_completed_synchronize_rcu();
	for (i = 0; req->node_slots && i < req->nr_node_slots; i++) {
		struct stack_depot_trie_node *node = req->node_slots[i].node;

		if (node && !trie_pool_mark_contains(mark, node)) {
			trie_add_free_node_locked(node, req->node_slots[i].size);
			req->node_slots[i].node = NULL;
		}
	}
	for (i = 0; req->child_slots && i < req->nr_child_slots; i++) {
		struct stack_depot_trie_child_array *array = req->child_slots[i].array;

		if (array &&
		    !trie_pool_mark_contains(mark,
					     trie_object_header(array))) {
			trie_free_object_locked(array, completed);
			req->child_slots[i].array = NULL;
		}
	}
	if (req->storage && *req->storage &&
	    !trie_pool_mark_contains(mark,
				      trie_object_header(*req->storage))) {
		trie_free_object_locked(*req->storage, completed);
		*req->storage = NULL;
	}
}

static void trie_pool_release_reused_objects(struct stack_depot_trie_alloc_request *req)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pool_lock, flags);
	trie_pool_release_reused_objects_locked(req);
	raw_spin_unlock_irqrestore(&pool_lock, flags);
}

/*
 * Reserve all pool-backed storage for one trie insertion transaction. The
 * request may be satisfied by reusable retired fragments or by carving one
 * contiguous mark from the current stackdepot pool, possibly after installing
 * @prealloc as a new pool. @mark records only the newly carved range so
 * rollback can rewind pool_offset; reused fragments are returned to their
 * freelists separately on failure. The caller must not publish any returned
 * storage until the trie and side-table transaction commits.
 */
static int __stack_depot_trie_pool_carve(struct stack_depot_trie_alloc_request *req)
{
	struct stack_depot_trie_pool_mark *mark;
	unsigned long flags;
	unsigned int i;
	size_t offset;
	size_t total = 0;
	void *pool;
	int ret = -EINVAL;

	if (!req || !req->txn)
		return -EINVAL;
	mark = &req->txn->pool;
	memset(mark, 0, sizeof(*mark));
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

	raw_spin_lock_irqsave(&pool_lock, flags);
	printk_deferred_enter();
	if (!stack_pools) {
		ret = -ENOSPC;
		goto out;
	}
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
		mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->pool_prealloc)) {
			ret = -ENOSPC;
			goto out_release_reused;
		}
		mark->added_pool = true;
	}
	if (WARN_ON_ONCE(pool_offset > DEPOT_POOL_SIZE))
		goto out_release_reused;
	if (total > DEPOT_POOL_SIZE - pool_offset) {
		mark->prev_offset = pool_offset;
		if (!depot_init_pool(req->pool_prealloc)) {
			ret = -ENOSPC;
			goto out_release_reused;
		}
		mark->added_pool = true;
	}

	mark->pool_index = pools_num - 1;
	pool = stack_pools[mark->pool_index];
	if (WARN_ON_ONCE(!pool))
		goto out_release_reused;

	mark->offset = pool_offset;
	mark->pool = pool;
	mark->size = total;
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

static int __stack_depot_trie_alloc_txn_reserve(struct stack_depot_trie_alloc_request *req)
{
	u32 leaf_id;
	int ret;

	if (!req || !req->txn)
		return -EINVAL;
	if (req->txn->leaf_id || req->txn->pool.size)
		return -EINVAL;

	leaf_id = __stack_depot_trie_side_table_prepare_id(req->side_prealloc);
	if (!leaf_id)
		return -ENOSPC;
	req->txn->leaf_id = leaf_id;

	ret = __stack_depot_trie_pool_carve(req);
	if (ret) {
		req->txn->leaf_id = 0;
		__stack_depot_trie_alloc_txn_rollback(req->txn);
		return ret;
	}

	return 0;
}

static int
__stack_depot_trie_alloc_txn_plan(const struct stack_depot_trie_root *root,
				  const unsigned long *entries,
				  unsigned int nr_entries,
				  struct stack_depot_trie_node_slot *node_slots,
				  unsigned int nr_node_slots,
				  struct stack_depot_trie_child_array_slot *child_slots,
				  unsigned int nr_child_slots,
				  struct stack_depot_trie_alloc_txn *txn,
				  struct stack_depot_trie_child_array **storage,
				  void **pool_prealloc,
				  struct stack_depot_trie_side_prealloc *side_prealloc,
				  struct stack_depot_trie_alloc_request *req)
{
	unsigned int nr_child_used;
	unsigned int nr_used;
	size_t storage_size;
	int ret;

	if (!root || !txn || !storage || !req)
		return -EINVAL;

	rcu_read_lock_sched_notrace();
	ret = __stack_depot_trie_insert_plan(root, NULL, entries, nr_entries,
					     node_slots, nr_node_slots, child_slots,
					     nr_child_slots, &storage_size, &nr_used,
					     &nr_child_used);
	rcu_read_unlock_sched_notrace();
	if (ret)
		return ret;

	memset(txn, 0, sizeof(*txn));
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
__stack_depot_trie_workspace_insert(struct stack_depot_trie_root *root,
				    const unsigned long *entries,
				    unsigned int nr_entries, void **pool_prealloc,
				    struct stack_depot_trie_side_prealloc *side_prealloc,
				    struct stack_depot_trie_alloc_workspace *workspace,
				    u32 *leaf_id)
{
	struct stack_depot_trie_child_array_slot *child_slots;
	struct stack_depot_trie_node_slot *node_slots;
	int ret;

	if (!workspace)
		return -EINVAL;

	memset(workspace, 0, sizeof(*workspace));
	node_slots = workspace->node_slots;
	child_slots = workspace->child_slots;
	ret = __stack_depot_trie_alloc_txn_plan(root,
						entries, nr_entries, node_slots,
						ARRAY_SIZE(workspace->node_slots), child_slots,
						ARRAY_SIZE(workspace->child_slots),
						&workspace->txn, &workspace->storage,
						pool_prealloc, side_prealloc,
						&workspace->req);
	if (ret)
		return ret;

	return __stack_depot_trie_alloc_txn_insert(root, &workspace->req, entries,
						nr_entries, workspace->scratch,
						ARRAY_SIZE(workspace->scratch), leaf_id);
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
trie_find_trylocked(struct stack_depot_trie_root *root,
		    const unsigned long *entries, unsigned int nr_entries,
		    raw_spinlock_t *workspace_lock)
{
	depot_stack_handle_t handle = 0;
	unsigned long flags;

	if (!raw_spin_trylock_irqsave(workspace_lock, flags))
		return 0;
	handle = trie_find_handle(root, entries, nr_entries);
	raw_spin_unlock_irqrestore(workspace_lock, flags);
	return handle;
}

static int
__stack_depot_trie_alloc_txn_insert(struct stack_depot_trie_root *root,
				    struct stack_depot_trie_alloc_request *req,
				    const unsigned long *entries,
				    unsigned int nr_entries, u32 *scratch,
				    unsigned int nr_scratch, u32 *leaf_id)
{
	struct stack_depot_trie_alloc_txn *txn;
	u32 id;
	struct stack_depot_trie_child_array *storage;
	int ret;

	if (!root || !req || !req->txn || !leaf_id)
		return -EINVAL;
	txn = req->txn;
	*leaf_id = 0;
	lockdep_assert_held(&stack_depot_trie_workspace_lock);

	ret = __stack_depot_trie_alloc_txn_reserve(req);
	if (ret)
		return ret;
	storage = req->storage ? *req->storage : NULL;

	id = txn->leaf_id;
	ret = __stack_depot_trie_insert_append_prepare(root, NULL, id, entries,
						       nr_entries, req->node_slots,
						       req->nr_node_slots, req->child_slots,
						       req->nr_child_slots, scratch,
						       nr_scratch, storage, req->storage_size);
	if (ret)
		goto rollback;

	__stack_depot_trie_side_table_commit_id(id);
	memset(txn, 0, sizeof(*txn));
	*leaf_id = id;
	return 0;

rollback:
	trie_pool_release_reused_objects(req);
	__stack_depot_trie_alloc_txn_rollback(req->txn);
	return ret;
}

static void __stack_depot_trie_alloc_txn_rollback(struct stack_depot_trie_alloc_txn *txn)
{
	unsigned long flags;
	bool rolled_back = true;

	if (!txn)
		return;

	if (txn->pool.size) {
		raw_spin_lock_irqsave(&pool_lock, flags);
		rolled_back = stack_depot_trie_pool_rollback_locked(&txn->pool);
		raw_spin_unlock_irqrestore(&pool_lock, flags);
		WARN_ON_ONCE(!rolled_back);
	}
	txn->leaf_id = 0;
	memset(&txn->pool, 0, sizeof(txn->pool));
}

static int trie_side_publish_locked(const struct stack_depot_trie_leaf_update *updates,
				    unsigned int nr_updates)
{
	struct stack_depot_trie_side_entry *chunks[STACK_DEPOT_TRIE_MAX_LEAF_UPDATES];
	unsigned int slots[STACK_DEPOT_TRIE_MAX_LEAF_UPDATES];
	u32 next_leaf_id = trie_side_table_next_id + 1;
	unsigned int i;

	lockdep_assert_held(&trie_side_table_lock);
	if ((!updates && nr_updates) || nr_updates > ARRAY_SIZE(chunks))
		return -EINVAL;

	for (i = 0; i < nr_updates; i++) {
		u32 leaf_id = updates[i].leaf_id;

		if (!updates[i].leaf)
			return -EINVAL;
		chunks[i] = trie_side_table_chunk_locked(leaf_id, &slots[i]);
		if (!chunks[i])
			return -EINVAL;
		if (leaf_id == next_leaf_id &&
		    trie_side_table_load_leaf(chunks[i], slots[i]))
			return -EINVAL;
	}

	/* Pairs with trie_side_table_load_leaf(). */
	for (i = 0; i < nr_updates; i++)
		rcu_assign_pointer(chunks[i][slots[i]].leaf, updates[i].leaf);

	return 0;
}

static int trie_side_publish(const struct stack_depot_trie_leaf_update *updates,
			     unsigned int nr_updates)
{
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&trie_side_table_lock, flags);
	ret = trie_side_publish_locked(updates, nr_updates);
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
	if (stack_depot_trie_enabled_param && stack_depot_trie_init_memblock()) {
		pr_warn("trie storage initialization failed, disabling trie storage\n");
		stack_depot_trie_enabled_param = false;
	}

	return 0;
}

/* Allocates a hash table via kvcalloc. Can be used after boot. */
int stack_depot_init(void)
{
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
	if (!ret && stack_depot_trie_enabled_param) {
		ret = stack_depot_trie_init(GFP_KERNEL);
		if (ret) {
			pr_warn("trie storage initialization failed, disabling trie storage\n");
			stack_depot_trie_enabled_param = false;
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
	stack->flags = flags & STACK_DEPOT_FLAGS_MASK;
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
	depot_flags_t mode = STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_COUNTABLE;
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
		/* Plain, refcounted, and countable records have distinct lifetimes. */
		if ((stack->flags & mode) != (flags & mode))
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
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	void *pool_prealloc = NULL;
	depot_stack_handle_t handle;
	unsigned long flags;
	bool can_alloc;
	bool retried = false;
	u32 leaf_id;
	int ret;

	workspace = stack_depot_trie_load_workspace();
	can_alloc = (depot_flags & STACK_DEPOT_FLAG_CAN_ALLOC) &&
		gfpflags_allow_spinning(alloc_flags);

retry:
	handle = trie_find_handle(&stack_depot_trie_root, entries, nr_entries);
	if (handle)
		return handle;
	/*
	 * No-spin callers cannot wait for the workspace lock or allocate side-table
	 * or pool storage. After the lockless lookup misses, trylock and recheck: a
	 * concurrent writer may have inserted the stack. Otherwise fail instead of
	 * spinning or publishing a new leaf.
	 */
	if (in_nmi() || !gfpflags_allow_spinning(alloc_flags))
		return trie_find_trylocked(&stack_depot_trie_root, entries,
					       nr_entries,
					       &stack_depot_trie_workspace_lock);

	ret = __stack_depot_trie_alloc_prealloc(alloc_flags, depot_flags,
						&pool_prealloc,
						&side_prealloc);
	if (ret)
		goto out_free;

	raw_spin_lock_irqsave(&stack_depot_trie_workspace_lock, flags);
	handle = trie_find_handle(&stack_depot_trie_root, entries, nr_entries);
	if (!handle) {
		ret = __stack_depot_trie_workspace_insert(&stack_depot_trie_root,
							  entries, nr_entries,
							  &pool_prealloc,
							  &side_prealloc, workspace,
							  &leaf_id);
		if (!ret)
			handle = __stack_depot_trie_handle(leaf_id);
	}
	raw_spin_unlock_irqrestore(&stack_depot_trie_workspace_lock, flags);
	if (!handle && ret == -ENOSPC && can_alloc && !retried) {
		retried = true;
		depot_try_keep_new_pool(&pool_prealloc);
		if (pool_prealloc) {
			free_pages((unsigned long)pool_prealloc, DEPOT_POOL_ORDER);
			pool_prealloc = NULL;
		}
		__stack_depot_trie_side_table_free_prealloc(&side_prealloc);
		goto retry;
	}

out_free:
	depot_try_keep_new_pool(&pool_prealloc);
	if (pool_prealloc)
		free_pages((unsigned long)pool_prealloc, DEPOT_POOL_ORDER);
	__stack_depot_trie_side_table_free_prealloc(&side_prealloc);
	return handle;
}

static depot_stack_handle_t
depot_save_stack_locked(struct list_head *bucket, unsigned long *entries,
			unsigned int nr_entries, u32 hash,
			depot_flags_t depot_flags, void **prealloc)
{
	struct stack_record *found;
	struct stack_record *new;

	lockdep_assert_held(&pool_lock);

	/* Try to find again, to avoid concurrently inserting duplicates. */
	found = find_stack(bucket, entries, nr_entries, hash, depot_flags);
	if (found)
		return found->handle.handle;
	new = depot_alloc_stack(entries, nr_entries, hash, depot_flags, prealloc);
	if (!new)
		return 0;

	/*
	 * This releases the stack record into the bucket and makes it visible to
	 * readers in find_stack().
	 */
	list_add_rcu(&new->hash_list, bucket);
	return new->handle.handle;
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
	bool trie_candidate;
	unsigned long flags;
	u32 hash;

	if (WARN_ON(depot_flags & ~STACK_DEPOT_FLAGS_MASK))
		return 0;
	if (WARN_ON_ONCE((depot_flags & STACK_DEPOT_FLAG_GET) &&
			 (depot_flags & STACK_DEPOT_FLAG_COUNTABLE)))
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
	if (nr_entries > CONFIG_STACKDEPOT_MAX_FRAMES)
		nr_entries = CONFIG_STACKDEPOT_MAX_FRAMES;

	trie_candidate = !(depot_flags & (STACK_DEPOT_FLAG_GET | STACK_DEPOT_FLAG_COUNTABLE)) &&
		__stack_depot_trie_ready();
	if (trie_candidate) {
		handle = stack_depot_trie_save(entries, nr_entries, alloc_flags,
					       depot_flags);
		if (handle)
			return handle;
		/* Keep trie failures visible; hash fallback hides trie pool pressure. */
		return 0;
	}

	hash = hash_stack(entries, nr_entries);
	bucket = &stack_table[hash & stack_hash_mask];
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
		handle = depot_save_stack_locked(bucket, entries, nr_entries,
						 hash, depot_flags, &prealloc);
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
	handle = depot_save_stack_locked(bucket, entries, nr_entries,
					 hash, depot_flags, &prealloc);
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

struct stack_record *__stack_depot_get_stack_record(depot_stack_handle_t handle)
{
	struct stack_record *stack;

	if (!handle)
		return NULL;
	if (WARN_ON_ONCE(__stack_depot_trie_leaf_id(handle)))
		return NULL;

	stack = depot_fetch_stack(handle);
	if (!stack)
		return NULL;
	if (WARN_ON_ONCE(!(stack->flags & STACK_DEPOT_FLAG_COUNTABLE)))
		return NULL;

	return stack;
}

static int
stack_depot_trie_child_lower_bound(const struct stack_depot_trie_child_array *array,
				   unsigned long frame, unsigned int *pos,
				   bool *found);
static inline unsigned int trie_child_array_storage_capacity(size_t storage_size);
static size_t trie_child_array_size_for_capacity(unsigned int capacity);
static bool
trie_parent_chain_matches_prefix(const struct stack_depot_trie_node *node,
				 const unsigned long *entries,
				 unsigned int nr_entries);

static inline size_t stack_depot_frame_run_entry_bytes(enum stack_depot_frame_mode mode)
{
	if (mode == STACK_DEPOT_FRAME_COMPRESSED)
		return sizeof(u32);
	return sizeof(unsigned long);
}

static inline size_t stack_depot_frame_run_bytes(const struct stack_depot_frame_run *run)
{
	return run->nr_entries * stack_depot_frame_run_entry_bytes(run->mode);
}

static int stack_depot_frame_run_validate(const struct stack_depot_frame_run *run)
{
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

	return 0;
}

static int frame_run_init_lows(const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_frame_run *run,
			       u32 *lows, unsigned int nr_lows)
{
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
	compressed = arch_stack_depot_frame_try_compress(entries[0], &low);
	if (compressed && lows)
		lows[0] = low;
	for (i = 1; i < nr_entries; i++) {
		bool next;

		next = arch_stack_depot_frame_try_compress(entries[i], &low);
		if (next != compressed)
			break;
		if (compressed && lows)
			lows[i] = low;
	}

	/* @i is the first non-matching frame, or @nr_entries if all matched. */
	run->mode = compressed ? STACK_DEPOT_FRAME_COMPRESSED : STACK_DEPOT_FRAME_RAW;
	run->nr_entries = i;

	return 0;
}

static int
__stack_depot_frame_run_init(const unsigned long *entries,
			     unsigned int nr_entries,
			     struct stack_depot_frame_run *run)
{
	return frame_run_init_lows(entries, nr_entries, run, NULL, 0);
}

static size_t __stack_depot_trie_node_size(const struct stack_depot_frame_run *run)
{
	size_t size;

	if (stack_depot_frame_run_validate(run))
		return 0;
	size = offsetof(struct stack_depot_trie_node, data);
	if (check_add_overflow(size, stack_depot_frame_run_bytes(run), &size))
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
	return 0;
}

static int
stack_depot_trie_node_frame(const struct stack_depot_trie_node *node,
			    unsigned int index, unsigned long *frame)
{
	u32 low;

	if (!node || !frame || index >= node->run.nr_entries)
		return -EINVAL;

	if (node->run.mode == STACK_DEPOT_FRAME_RAW) {
		memcpy(frame, node->data + index * sizeof(*frame),
		       sizeof(*frame));
		return 0;
	}

	memcpy(&low, node->data + index * sizeof(low), sizeof(low));
	arch_stack_depot_frame_decompress(low, frame);

	return 0;
}

static int
stack_depot_trie_node_first_frame(const struct stack_depot_trie_node *node,
				  unsigned long *frame)
{
	return stack_depot_trie_node_frame(node, 0, frame);
}

static int
trie_node_stack_len(const struct stack_depot_trie_node *node,
		    unsigned int *stack_len)
{
	unsigned int depth = 0;
	unsigned int total = 0;

	if (!node || !stack_len)
		return -EINVAL;

	for (; node; node = trie_load_parent(node)) {
		if (depth++ >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return -EINVAL;
		if (total > CONFIG_STACKDEPOT_MAX_FRAMES - node->run.nr_entries)
			return -EINVAL;
		total += node->run.nr_entries;
	}

	*stack_len = total;
	return 0;
}

static int
__stack_depot_trie_node_init(void *storage, size_t storage_size,
			     const struct stack_depot_trie_node *parent, u32 leaf_id,
			     const unsigned long *entries,
			     unsigned int nr_entries, u32 *scratch,
			     unsigned int nr_scratch)
{
	const struct stack_depot_trie_node *parent_node = parent;
	struct stack_depot_trie_node *node = storage;
	struct stack_depot_frame_run run;
	unsigned int parent_len = 0;
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
		if (trie_node_stack_len(parent_node, &parent_len) ||
		    parent_len > CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;
	}

	/* Caller-owned storage is not publishable unless the payload write succeeds. */
	if (run.mode == STACK_DEPOT_FRAME_COMPRESSED)
		/* Copy low-bit payloads staged by frame_run_init_lows(). */
		memcpy(node->data, scratch, stack_depot_frame_run_bytes(&run));
	else
		memcpy(node->data, entries, stack_depot_frame_run_bytes(&run));

	node->parent = parent_node;
	node->children = NULL;
	node->leaf_id = leaf_id;
	node->run = run;
	return 0;
}

static int
__stack_depot_trie_node_init_slice(void *storage, size_t storage_size,
				   const struct stack_depot_trie_node *parent,
				   u32 leaf_id,
				   const struct stack_depot_trie_node *src_node,
				   unsigned int start,
				   unsigned int nr_entries)
{
	const struct stack_depot_trie_node *parent_node = parent;
	const struct stack_depot_trie_node *src = src_node;
	struct stack_depot_trie_node *node = storage;
	struct stack_depot_frame_run run;
	size_t entry_bytes;
	size_t src_size;
	unsigned int parent_len = 0;
	int ret;

	if (!node || !src)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)node, __alignof__(*node)))
		return -EINVAL;

	ret = stack_depot_frame_run_slice(&src->run, start, nr_entries, &run);
	if (ret)
		return ret;
	if (storage_size < __stack_depot_trie_node_size(&run))
		return -EINVAL;
	src_size = __stack_depot_trie_node_size(&src->run);
	if (!src_size)
		return -EINVAL;
	if (parent_node) {
		if (trie_node_stack_len(parent_node, &parent_len) ||
		    parent_len > CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;
	}

	entry_bytes = stack_depot_frame_run_entry_bytes(src->run.mode);
	memcpy(node->data, src->data + start * entry_bytes,
	       stack_depot_frame_run_bytes(&run));
	node->parent = parent_node;
	node->children = NULL;
	node->leaf_id = leaf_id;
	node->run = run;
	return 0;
}

static unsigned int
__stack_depot_trie_node_match(const struct stack_depot_trie_node *node,
			      const unsigned long *entries,
			      unsigned int nr_entries)
{
	unsigned int limit;
	unsigned int i;

	if (!node || !entries || !nr_entries)
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

static const struct stack_depot_trie_node *
trie_load_parent(const struct stack_depot_trie_node *node)
{
	const struct stack_depot_trie_node __rcu * const *slot;

	slot = (const struct stack_depot_trie_node __rcu * const *)&node->parent;
	return rcu_dereference_check(*slot,
				     lockdep_is_held(&stack_depot_trie_workspace_lock) ||
				     rcu_read_lock_sched_held());
}

static void
trie_publish_parent(struct stack_depot_trie_node *child,
		    const struct stack_depot_trie_node *parent)
{
	const struct stack_depot_trie_node __rcu **slot;

	slot = (const struct stack_depot_trie_node __rcu **)&child->parent;
	rcu_assign_pointer(*slot, parent);
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

static const struct stack_depot_trie_child_array *
trie_load_children_slot(const struct stack_depot_trie_child_array * const *slot)
{
	const struct stack_depot_trie_child_array __rcu * const *rcu_slot;

	rcu_slot = (const struct stack_depot_trie_child_array __rcu * const *)slot;
	return rcu_dereference_check(*rcu_slot,
				     lockdep_is_held(&stack_depot_trie_workspace_lock) ||
				     rcu_read_lock_sched_held());
}

static const struct stack_depot_trie_node *
trie_child_array_load_child(const struct stack_depot_trie_child_array *array,
			    unsigned int pos)
{
	const struct stack_depot_trie_node __rcu * const *slot;

	slot = (const struct stack_depot_trie_node __rcu * const *)&array->children[pos];
	return rcu_dereference_check(*slot,
				     lockdep_is_held(&stack_depot_trie_workspace_lock) ||
				     rcu_read_lock_sched_held());
}

static void
trie_child_array_publish_child(struct stack_depot_trie_child_array *array,
			       unsigned int pos,
			       const struct stack_depot_trie_node *child)
{
	const struct stack_depot_trie_node __rcu **slot;

	slot = (const struct stack_depot_trie_node __rcu **)&array->children[pos];
	rcu_assign_pointer(*slot, child);
}

static void
trie_publish_children_slot(const struct stack_depot_trie_child_array **slot,
			   const struct stack_depot_trie_child_array *children)
{
	const struct stack_depot_trie_child_array __rcu **rcu_slot;

	rcu_slot = (const struct stack_depot_trie_child_array __rcu **)slot;
	rcu_assign_pointer(*rcu_slot, children);
}

static bool
trie_child_array_can_append(const struct stack_depot_trie_child_array *array,
			    unsigned int pos)
{
	unsigned int nr_children;

	if (!array)
		return false;
	nr_children = READ_ONCE(array->nr_children);
	return pos == nr_children && nr_children < array->capacity;
}

static void
trie_child_array_replace_at(const struct stack_depot_trie_child_array *old_array,
			    const struct stack_depot_trie_node *new_child,
			    struct stack_depot_trie_child_array *new_storage,
			    size_t new_storage_size,
			    unsigned int pos)
{
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned int i;

	new_array->nr_children = old_array->nr_children;
	new_array->capacity = trie_child_array_storage_capacity(new_storage_size);
	for (i = 0; i < old_array->nr_children; i++)
		new_array->children[i] = trie_child_array_load_child(old_array, i);
	new_array->children[pos] = new_child;
	for (i = old_array->nr_children; i < new_array->capacity; i++)
		new_array->children[i] = NULL;
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
	if (old_node->leaf_id)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)slot->node,
			__alignof__(struct stack_depot_trie_node)))
		return -EINVAL;

	size = __stack_depot_trie_node_size(&old_node->run);
	if (!size || slot->size < size)
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
		child = (struct stack_depot_trie_node *)trie_child_array_load_child(children, i);
		trie_publish_parent(child, parent);
	}
}

static int
trie_promote_child(struct stack_depot_trie_root *root,
		   struct stack_depot_trie_node *parent,
		   const struct stack_depot_trie_child_array *old_array,
		   unsigned int pos,
		   const struct stack_depot_trie_node *child, u32 leaf_id,
		   const struct stack_depot_trie_node_slot *slot,
		   struct stack_depot_trie_child_array *new_storage,
		   size_t new_storage_size)
{
	const struct stack_depot_trie_child_array **publish_slot;
	struct stack_depot_trie_leaf_update update;
	size_t child_size;
	int ret;

	if (!leaf_id)
		return -EINVAL;
	if (!old_array || pos >= READ_ONCE(old_array->nr_children) ||
	    trie_child_array_load_child(old_array, pos) != child)
		return -EINVAL;
	if (!child || !slot || !slot->node || !new_storage)
		return -EINVAL;
	if (child->parent != parent || child->leaf_id)
		return -EINVAL;
	child_size = __stack_depot_trie_node_size(&child->run);
	if (!child_size || slot->size < child_size)
		return -EINVAL;
	ret = trie_clone_promoted_node(child, leaf_id, slot);
	if (ret)
		return ret;
	update.leaf_id = leaf_id;
	update.leaf = slot->node;
	ret = trie_side_publish(&update, 1);
	if (ret)
		return ret;
	trie_child_array_replace_at(old_array, slot->node, new_storage,
				    new_storage_size, pos);
	trie_reparent_children(slot->node);

	publish_slot = trie_publish_slot(root, parent);
	/* Publish the fully initialized replacement array last. */
	trie_publish_children_slot(publish_slot, new_storage);
	trie_retire_object_node(old_array, child, child_size);
	return 0;
}

static int
__stack_depot_trie_append_chain(const struct stack_depot_trie_node *parent,
				u32 leaf_id,
				const unsigned long *entries,
				unsigned int nr_entries,
				const struct stack_depot_trie_node_slot *node_slots,
				unsigned int nr_node_slots,
				const struct stack_depot_trie_child_array_slot *child_slots,
				unsigned int nr_child_slots, u32 *scratch,
				unsigned int nr_scratch,
				const struct stack_depot_trie_node **head,
				const struct stack_depot_trie_node **tail)
{
	const struct stack_depot_trie_node *prev = parent;
	unsigned int child_slots_needed;
	unsigned int stack_len = 0;
	unsigned int pos = 0;
	unsigned int used = 0;
	unsigned int i;

	if (!leaf_id || !entries || !nr_entries || !node_slots || !head || !tail)
		return -EINVAL;
	if (parent && trie_node_stack_len(parent, &stack_len))
		return -EINVAL;

	while (pos < nr_entries) {
		struct stack_depot_frame_run run;
		struct stack_depot_trie_node *node;
		size_t size;
		u32 id;

		if (used >= nr_node_slots)
			return -EINVAL;
		node = node_slots[used].node;
		if (!node)
			return -EINVAL;
		if (__stack_depot_frame_run_init(&entries[pos], nr_entries - pos,
						 &run))
			return -EINVAL;
		if (run.mode == STACK_DEPOT_FRAME_COMPRESSED &&
		    (!scratch || nr_scratch < run.nr_entries))
			return -EINVAL;
		if (stack_len > CONFIG_STACKDEPOT_MAX_FRAMES - run.nr_entries)
			return -EINVAL;
		size = __stack_depot_trie_node_size(&run);
		if (!size || node_slots[used].size < size)
			return -EINVAL;
		if (!IS_ALIGNED((unsigned long)node,
				__alignof__(struct stack_depot_trie_node)))
			return -EINVAL;

		id = pos + run.nr_entries == nr_entries ? leaf_id : 0;
		if (__stack_depot_trie_node_init(node, node_slots[used].size, prev,
						 id, &entries[pos], run.nr_entries,
						 scratch, nr_scratch))
			return -EINVAL;

		stack_len += run.nr_entries;
		prev = node;
		pos += run.nr_entries;
		used++;
	}

	child_slots_needed = used > 1 ? used - 1 : 0;
	if (child_slots_needed) {
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
		}
	}

	for (i = 0; i + 1 < used; i++) {
		const struct stack_depot_trie_node *next = node_slots[i + 1].node;
		struct stack_depot_trie_node *node = node_slots[i].node;
		struct stack_depot_trie_child_array *array = child_slots[i].array;
		size_t size = child_slots[i].size;

		if (__stack_depot_trie_child_array_insert(NULL, next, array, size))
			return -EINVAL;
		node->children = array;
	}

	*head = node_slots[0].node;
	*tail = node_slots[used - 1].node;
	return 0;
}

static int trie_publish_append_prepare(struct stack_depot_trie_root *root,
				       struct stack_depot_trie_node *parent,
				       const struct stack_depot_trie_node *head,
				       struct stack_depot_trie_child_array *new_storage,
				       size_t new_storage_size, u32 leaf_id,
				       const struct stack_depot_trie_node *leaf)
{
	const struct stack_depot_trie_child_array *old_array;
	const struct stack_depot_trie_child_array **slot;
	struct stack_depot_trie_child_array *new_array = new_storage;
	size_t storage_size = new_storage_size;
	size_t new_size;
	int ret;

	if ((root && parent) || (!root && !parent) || !head)
		return -EINVAL;
	if (head->parent != parent)
		return -EINVAL;

	if (root)
		slot = &root->children;
	else
		slot = &parent->children;

	old_array = trie_load_children_slot(slot);
	new_size = old_array ? READ_ONCE(old_array->nr_children) + 1 : 1;
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
		{
			struct stack_depot_trie_leaf_update update = {
				.leaf_id = leaf_id,
				.leaf = leaf,
			};

			if (!leaf_id || !leaf)
				return -EINVAL;
			ret = trie_side_publish(&update, 1);
			if (ret)
				return ret;
		}
		trie_child_array_publish_child((struct stack_depot_trie_child_array *)old_array,
					       pos, head);
		/* Only tail append mutates a live array; COW arrays are unpublished. */
		WRITE_ONCE(((struct stack_depot_trie_child_array *)old_array)->nr_children,
			   pos + 1);
		return 0;
	}
	if (storage_size < new_size)
		return -EINVAL;
	if (old_array &&
	    new_array == old_array)
		return -EINVAL;
	if (__stack_depot_trie_child_array_insert(old_array, head, new_array, storage_size))
		return -EINVAL;
	{
		struct stack_depot_trie_leaf_update update = {
			.leaf_id = leaf_id,
			.leaf = leaf,
		};

		if (!leaf_id || !leaf)
			return -EINVAL;
		ret = trie_side_publish(&update, 1);
		if (ret)
			return ret;
	}
	/* Publish the fully initialized replacement array last. */
	trie_publish_children_slot(slot, new_array);
	trie_retire_object_node(old_array, NULL, 0);
	return 0;
}

static int
__stack_depot_trie_lookup_step(const struct stack_depot_trie_root *root,
			       const struct stack_depot_trie_node *parent,
			       const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_lookup *lookup)
{
	const struct stack_depot_trie_child_array *children;
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

	if (root)
		children = trie_load_children_slot(&root->children);
	else
		children = trie_load_children_slot(&parent->children);

	tmp.status = STACK_DEPOT_TRIE_LOOKUP_APPEND;
	tmp.children = children;
	tmp.node = NULL;
	tmp.matched = 0;
	tmp.pos = 0;
	if (!children) {
		*lookup = tmp;
		return 0;
	}

	key = entries[0];
	if (stack_depot_trie_child_lower_bound(children, key, &pos, &found))
		return -EINVAL;
	if (!found) {
		tmp.pos = pos;
		*lookup = tmp;
		return 0;
	}

	node = trie_child_array_load_child(children, pos);
	if (!node)
		return -EINVAL;
	/*
	 * Do not require direct parent identity here. COW updates may publish a
	 * child whose parent chain is an equivalent replacement prefix; the finder
	 * has enough input prefix context to validate that equivalence.
	 */

	matched = __stack_depot_trie_node_match(node, entries, nr_entries);
	if (!matched)
		return -EINVAL;

	tmp.node = node;
	tmp.matched = matched;
	tmp.pos = pos;
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

static const struct stack_depot_trie_node *
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
			    const struct stack_depot_trie_child_array *old_array,
			    unsigned int pos,
			    const struct stack_depot_trie_node *child,
			    unsigned int matched, u32 leaf_id,
			    const unsigned long *entries,
			    unsigned int nr_entries,
			    const struct stack_depot_trie_node_slot *node_slots,
			    unsigned int nr_node_slots,
			    const struct stack_depot_trie_child_array_slot *child_slots,
			    unsigned int nr_child_slots, u32 *scratch,
			    unsigned int nr_scratch,
			    struct stack_depot_trie_child_array *new_storage,
			    size_t new_storage_size);

static int
__stack_depot_trie_insert_append_prepare(struct stack_depot_trie_root *root,
					 struct stack_depot_trie_node *parent,
					 u32 leaf_id,
					 const unsigned long *entries,
					 unsigned int nr_entries,
					 const struct stack_depot_trie_node_slot *node_slots,
					 unsigned int nr_node_slots,
					 const struct stack_depot_trie_child_array_slot
					 *child_slots,
					 unsigned int nr_child_slots, u32 *scratch,
					 unsigned int nr_scratch,
					 struct stack_depot_trie_child_array *new_storage,
					 size_t new_storage_size)
{
	const struct stack_depot_trie_node *head;
	const struct stack_depot_trie_node *last;
	struct stack_depot_trie_lookup lookup;
	int ret;

	if (!leaf_id)
		return -EINVAL;

	for (;;) {
		ret = __stack_depot_trie_lookup_step(root, parent, entries, nr_entries, &lookup);
		if (ret)
			return ret;
		if (lookup.status != STACK_DEPOT_TRIE_LOOKUP_DESCEND)
			break;
		/* Insert callers serialize writers and may publish below this node. */
		parent = (struct stack_depot_trie_node *)lookup.node;
		root = NULL;
		entries += lookup.matched;
		nr_entries -= lookup.matched;
	}

	if (!entries || !nr_entries)
		return -EINVAL;
	if (lookup.status == STACK_DEPOT_TRIE_LOOKUP_SPLIT)
		return trie_split_child(root, parent, lookup.children, lookup.pos,
					lookup.node, lookup.matched, leaf_id, entries,
					nr_entries, node_slots, nr_node_slots, child_slots,
					nr_child_slots, scratch, nr_scratch, new_storage,
					new_storage_size);
	if (lookup.status == STACK_DEPOT_TRIE_LOOKUP_PROMOTE) {
		if (!node_slots || !nr_node_slots)
			return -EINVAL;
		ret = trie_promote_child(root, parent, lookup.children, lookup.pos,
					 lookup.node, leaf_id, &node_slots[0],
					 new_storage, new_storage_size);
		if (ret)
			return ret;
		return 0;
	}
	if (lookup.status != STACK_DEPOT_TRIE_LOOKUP_APPEND)
		return -EINVAL;

	ret = __stack_depot_trie_append_chain(parent, leaf_id, entries, nr_entries,
					      node_slots, nr_node_slots, child_slots,
					      nr_child_slots, scratch, nr_scratch,
					      &head, &last);
	if (ret)
		return ret;
	ret = trie_publish_append_prepare(root, parent, head, new_storage,
					  new_storage_size, leaf_id, last);
	if (ret)
		return ret;

	return 0;
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

static bool
trie_parent_chain_matches_prefix(const struct stack_depot_trie_node *node,
				 const unsigned long *entries,
				 unsigned int nr_entries)
{
	const struct stack_depot_trie_node *cur;
	unsigned int depth = 0;
	unsigned int pos;
	unsigned int i;

	if (!node)
		return nr_entries == 0;
	if (!entries || trie_node_stack_len(node, &pos) || pos != nr_entries)
		return false;

	cur = node;
	while (cur) {
		if (depth++ >= CONFIG_STACKDEPOT_MAX_FRAMES)
			return false;
		if (cur->run.nr_entries > pos)
			return false;
		pos -= cur->run.nr_entries;

		for (i = 0; i < cur->run.nr_entries; i++) {
			unsigned long frame;

			if (stack_depot_trie_node_frame(cur, i, &frame) ||
			    frame != entries[pos + i])
				return false;
		}

		cur = trie_load_parent(cur);
	}

	return !pos;
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
	const struct stack_depot_trie_node *parent;
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
	if (!child->leaf_id && !trie_load_children_slot(&child->children))
		return -EINVAL;
	if (nr_node_slots < 2 || nr_child_slots < 1)
		return -EINVAL;
	if (stack_depot_frame_run_slice(&child->run, 0, matched, &prefix_run) ||
	    stack_depot_frame_run_slice(&child->run, matched,
					child->run.nr_entries - matched,
					&old_tail_run))
		return -EINVAL;

	has_new_tail = matched < nr_entries;
	parent = trie_load_parent(child);
	if (parent) {
		if (trie_node_stack_len(parent, &prefix_stack_len))
			return -EINVAL;
	} else {
		prefix_stack_len = 0;
	}
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

static int
__stack_depot_trie_insert_plan(const struct stack_depot_trie_root *root,
			       const struct stack_depot_trie_node *parent,
			       const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_node_slot *node_slots,
			       unsigned int nr_node_slots,
			       struct stack_depot_trie_child_array_slot *child_slots,
			       unsigned int nr_child_slots, size_t *new_storage_size,
			       unsigned int *nr_used, unsigned int *nr_child_used)
{
	const struct stack_depot_trie_child_array *children;
	const struct stack_depot_trie_node *child;
	unsigned int nr_children;
	unsigned int parent_len = 0;
	unsigned int matched;
	unsigned int pos;
	bool found;

	if (!entries || !nr_entries || !node_slots || !new_storage_size ||
	    !nr_used || !nr_child_used)
		return -EINVAL;
	if ((root && parent) || (!root && !parent))
		return -EINVAL;

	for (;;) {
		if (parent && trie_node_stack_len(parent, &parent_len))
			return -EINVAL;
		if (root)
			children = trie_load_children_slot(&root->children);
		else
			children = trie_load_children_slot(&parent->children);
		if (!children) {
			if (trie_plan_append_chain(parent ? parent_len : 0,
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
			if (trie_plan_append_chain(parent ? parent_len : 0,
						   entries, nr_entries, node_slots,
						   nr_node_slots, child_slots,
						   nr_child_slots, nr_used,
						   nr_child_used))
				return -EINVAL;
			if (trie_child_array_can_append(children, pos)) {
				*new_storage_size = 0;
				return 0;
			}
			nr_children = READ_ONCE(children->nr_children);
			*new_storage_size = __stack_depot_trie_child_array_size(nr_children + 1);
			return *new_storage_size ? 0 : -EINVAL;
		}

		child = trie_child_array_load_child(children, pos);
		if (!child || trie_load_parent(child) != parent)
			return -EINVAL;
		if (parent_len > CONFIG_STACKDEPOT_MAX_FRAMES - child->run.nr_entries)
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

static unsigned int trie_leaf_stack_len(const struct stack_depot_trie_node *leaf)
{
	unsigned int total;

	if (!leaf || !leaf->leaf_id)
		return 0;
	if (trie_node_stack_len(leaf, &total))
		return 0;

	return total;
}

static unsigned int trie_print_handle(depot_stack_handle_t handle, int spaces)
{
	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];
	unsigned int max_entries = ARRAY_SIZE(entries);
	unsigned int nr_entries;

	nr_entries = __stack_depot_trie_fetch_handle_into(handle, entries, max_entries);
	if (nr_entries)
		stack_trace_print(entries, nr_entries, spaces);

	return nr_entries;
}

static int
trie_snprint_handle(depot_stack_handle_t handle, char *buf, size_t size,
		    int spaces)
{
	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];
	unsigned int max_entries = ARRAY_SIZE(entries);
	unsigned int nr_entries;

	nr_entries = __stack_depot_trie_fetch_handle_into(handle, entries, max_entries);
	if (!nr_entries)
		return 0;

	return stack_trace_snprint(buf, size, entries, nr_entries, spaces);
}

static unsigned int
__stack_depot_trie_fetch_into(const struct stack_depot_trie_node *leaf,
			      unsigned long *entries,
			      unsigned int max_entries)
{
	const struct stack_depot_trie_node *node;
	unsigned int total;
	unsigned int seen = 0;
	unsigned int pos;
	unsigned int i;

	if (!entries)
		return 0;
	total = trie_leaf_stack_len(leaf);
	if (!total)
		return 0;
	if (max_entries < total)
		return 0;

	pos = total;
	for (node = leaf; node; node = trie_load_parent(node)) {
		if (node->run.nr_entries > pos)
			return 0;
		pos -= node->run.nr_entries;
		for (i = 0; i < node->run.nr_entries; i++) {
			if (stack_depot_trie_node_frame(node, i, &entries[pos + i]))
				return 0;
			seen++;
		}
	}
	if (seen != total || pos)
		return 0;

	kmsan_unpoison_memory(entries, total * sizeof(*entries));
	return total;
}

static unsigned int
__stack_depot_trie_fetch_handle_into(depot_stack_handle_t handle,
				     unsigned long *entries,
				     unsigned int max_entries)
{
	const struct stack_depot_trie_node *leaf;
	u32 leaf_id;
	unsigned int nr_entries;

	if (!handle || !entries || !max_entries)
		return 0;

	leaf_id = __stack_depot_trie_leaf_id(handle);
	if (!leaf_id)
		return 0;

	rcu_read_lock_sched_notrace();
	leaf = __stack_depot_trie_side_table_lookup(leaf_id);
	if (WARN_ONCE(!leaf, "corrupt trie handle %08x\n", handle)) {
		rcu_read_unlock_sched_notrace();
		return 0;
	}
	nr_entries = __stack_depot_trie_fetch_into(leaf, entries, max_entries);
	rcu_read_unlock_sched_notrace();

	return nr_entries;
}

static inline unsigned int trie_child_array_storage_capacity(size_t storage_size)
{
	if (storage_size < sizeof(struct stack_depot_trie_child_array))
		return 0;
	storage_size -= sizeof(struct stack_depot_trie_child_array);
	return storage_size / sizeof(struct stack_depot_trie_node *);
}

static size_t trie_child_array_size_for_capacity(unsigned int capacity)
{
	size_t size;

	size = struct_size_t(struct stack_depot_trie_child_array, children,
			     capacity);
	if (size == SIZE_MAX)
		return 0;

	return ALIGN(size, sizeof(unsigned long));
}

static inline size_t __stack_depot_trie_child_array_size(unsigned int nr_children)
{
	unsigned int capacity = nr_children ? roundup_pow_of_two(nr_children) : 0;

	return trie_child_array_size_for_capacity(capacity);
}

static int
__stack_depot_trie_child_array_init(void *storage, size_t storage_size,
				    const struct stack_depot_trie_node * const *nodes,
				    unsigned int nr_children)
{
	struct stack_depot_trie_child_array *array = storage;
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

		if (stack_depot_trie_node_first_frame(nodes[i], &frame))
			return -EINVAL;
		if (!__stack_depot_trie_node_size(&nodes[i]->run))
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
	for (i = nr_children; i < capacity; i++)
		array->children[i] = NULL;

	return 0;
}

static int
__stack_depot_trie_split_child_array_init(void *storage, size_t storage_size,
					  const struct stack_depot_trie_node *old_tail,
					  const struct stack_depot_trie_node *new_head)
{
	const struct stack_depot_trie_node *children[2];
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

static int trie_split_subtree_prepare(const struct stack_depot_trie_node *child,
				      unsigned int matched,
				      u32 leaf_id, const unsigned long *entries,
				      unsigned int nr_entries,
				      const struct stack_depot_trie_node_slot *node_slots,
				      unsigned int nr_node_slots,
				      const struct stack_depot_trie_child_array_slot *child_slots,
				      unsigned int nr_child_slots, u32 *scratch,
				      unsigned int nr_scratch,
				      const struct stack_depot_trie_node **prefix)
{
	const struct stack_depot_trie_child_array *child_children;
	const struct stack_depot_trie_node *child_parent;
	const unsigned long *tail_entries;
	const struct stack_depot_trie_node *new_head = NULL;
	const struct stack_depot_trie_node *new_tail = NULL;
	struct stack_depot_trie_leaf_update updates[2];
	struct stack_depot_trie_node *old_tail;
	struct stack_depot_trie_node *pref;
	unsigned int child_slots_needed;
	unsigned int nr_updates = 0;
	u32 prefix_leaf_id;
	void *split_array;
	size_t split_array_size;
	unsigned int tail_len;
	bool has_new_tail;
	int ret;

	if (!prefix || !child || !leaf_id || !entries ||
	    !nr_entries || !node_slots || !child_slots)
		return -EINVAL;
	if (!matched || matched >= child->run.nr_entries || matched > nr_entries)
		return -EINVAL;
	child_children = trie_load_children_slot(&child->children);
	if (!child->leaf_id && !child_children)
		return -EINVAL;
	child_parent = trie_load_parent(child);

	has_new_tail = matched < nr_entries;
	if (nr_node_slots < 2 || nr_child_slots < 1)
		return -EINVAL;
	if (has_new_tail && nr_node_slots < 3)
		return -EINVAL;
	child_slots_needed = 1 + (nr_node_slots > 3 ? nr_node_slots - 3 : 0);
	if (nr_child_slots != child_slots_needed)
		return -EINVAL;

	pref = node_slots[0].node;
	old_tail = node_slots[1].node;
	prefix_leaf_id = has_new_tail ? 0 : leaf_id;
	ret = __stack_depot_trie_node_init_slice(pref, node_slots[0].size,
						 child_parent, prefix_leaf_id,
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
						      scratch, nr_scratch, &new_head, &new_tail);
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
	ret = trie_side_publish(updates, nr_updates);
	if (ret) {
		memset(split_array, 0, split_array_size);
		return ret;
	}

	old_tail->children = child_children;
	pref->children = child_slots[0].array;
	trie_reparent_children(old_tail);
	*prefix = pref;
	return 0;
}

static int trie_split_child(struct stack_depot_trie_root *root,
			    struct stack_depot_trie_node *parent,
			    const struct stack_depot_trie_child_array *old_array,
			    unsigned int pos,
			    const struct stack_depot_trie_node *child,
			    unsigned int matched, u32 leaf_id,
			    const unsigned long *entries,
			    unsigned int nr_entries,
			    const struct stack_depot_trie_node_slot *node_slots,
			    unsigned int nr_node_slots,
			    const struct stack_depot_trie_child_array_slot *child_slots,
			    unsigned int nr_child_slots, u32 *scratch,
			    unsigned int nr_scratch,
			    struct stack_depot_trie_child_array *new_storage,
			    size_t new_storage_size)
{
	const struct stack_depot_trie_child_array **publish_slot;
	const struct stack_depot_trie_node *prefix;
	size_t child_size;
	int ret;

	if (!child)
		return -EINVAL;
	if (child->parent != parent)
		return -EINVAL;
	if (!old_array || pos >= READ_ONCE(old_array->nr_children) ||
	    old_array->children[pos] != child)
		return -EINVAL;

	publish_slot = trie_publish_slot(root, parent);
	if (!publish_slot)
		return -EINVAL;

	child_size = __stack_depot_trie_node_size(&child->run);
	if (!child_size)
		return -EINVAL;

	ret = trie_split_subtree_prepare(child, matched, leaf_id, entries,
					 nr_entries, node_slots, nr_node_slots,
					 child_slots, nr_child_slots, scratch,
					 nr_scratch, &prefix);
	if (ret)
		return ret;

	trie_child_array_replace_at(old_array, prefix, new_storage,
				    new_storage_size, pos);
	/* Publish the fully initialized replacement array last. */
	trie_publish_children_slot(publish_slot, new_storage);
	trie_retire_object_node(old_array, child, child_size);
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

	right = READ_ONCE(array->nr_children);
	while (left < right) {
		unsigned int mid = left + (right - left) / 2;
		const struct stack_depot_trie_node *node;
		unsigned long mid_frame;

		node = trie_child_array_load_child(array, mid);
		if (!node) {
			/* Tail append may produce a transient lockless lookup miss. */
			right = mid;
			continue;
		}
		if (stack_depot_trie_node_first_frame(node, &mid_frame))
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

static int
__stack_depot_trie_child_array_insert(const struct stack_depot_trie_child_array *old,
				      const struct stack_depot_trie_node *node,
				      struct stack_depot_trie_child_array *new_storage,
				      size_t new_storage_size)
{
	struct stack_depot_trie_child_array *new_array = new_storage;
	unsigned int nr_old;
	unsigned int pos;
	unsigned int i;
	unsigned long frame;
	size_t node_size;
	bool found;

	if (!node || !new_array || stack_depot_trie_node_first_frame(node, &frame))
		return -EINVAL;
	node_size = __stack_depot_trie_node_size(&node->run);
	if (!node_size)
		return -EINVAL;
	if (!IS_ALIGNED((unsigned long)new_array, __alignof__(*new_array)))
		return -EINVAL;
	if (!frame)
		return -EINVAL;
	if (old == new_array)
		return -EINVAL;
	if (old && !IS_ALIGNED((unsigned long)old, __alignof__(*old)))
		return -EINVAL;

	nr_old = old ? old->nr_children : 0;
	if (new_storage_size < __stack_depot_trie_child_array_size(nr_old + 1))
		return -EINVAL;

	if (old) {
		if (stack_depot_trie_child_lower_bound(old, frame, &pos,
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
	if (old) {
		for (i = 0; i < pos; i++)
			new_array->children[i] = trie_child_array_load_child(old, i);
	}
	new_array->children[pos] = node;
	if (old) {
		for (i = pos; i < nr_old; i++)
			new_array->children[i + 1] = trie_child_array_load_child(old, i);
	}
	for (i = nr_old + 1; i < new_array->capacity; i++)
		new_array->children[i] = NULL;

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

	stack = depot_fetch_stack(handle);
	if (!stack)
		return 0;
	nr_entries = stack->size;
	if (!nr_entries || nr_entries > max_entries)
		return 0;

	memcpy(entries, stack->entries, nr_entries * sizeof(*entries));
	kmsan_unpoison_memory(entries, nr_entries * sizeof(*entries));
	return nr_entries;
}
EXPORT_SYMBOL_GPL(stack_depot_fetch_into);

void stack_depot_put(depot_stack_handle_t handle)
{
	struct stack_record *stack;

	if (!handle || stack_depot_disabled)
		return;
	if (WARN_ON_ONCE(__stack_depot_trie_leaf_id(handle)))
		return;

	stack = depot_fetch_stack(handle);
	/*
	 * Should always be able to find the stack record, otherwise this is an
	 * unbalanced put attempt (or corrupt handle).
	 */
	if (WARN(!stack, "corrupt handle or unbalanced %s()", __func__))
		return;
	if (WARN_ON_ONCE(!(stack->flags & STACK_DEPOT_FLAG_GET)))
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
