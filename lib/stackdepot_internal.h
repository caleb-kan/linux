/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _STACKDEPOT_INTERNAL_H
#define _STACKDEPOT_INTERNAL_H

#include <linux/limits.h>
#include <linux/stackdepot.h>
#include <linux/types.h>

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

struct stack_depot_frame_run {
	unsigned int nr_entries;
	u16 bytes;
	u8 mode;
	u8 prefix_id;
};

static_assert(CONFIG_STACKDEPOT_MAX_FRAMES * sizeof(unsigned long) <= U16_MAX);

bool __stack_depot_trie_enabled(void);
void __stack_depot_trie_set_enabled(bool enabled);

struct stack_depot_trie_node_slot {
	void *node;
	size_t size;
};

struct stack_depot_trie_child_array_slot {
	void *array;
	size_t size;
};

struct stack_depot_trie_child_array;

struct stack_depot_trie_root {
	const struct stack_depot_trie_child_array *children;
};

struct stack_depot_trie_lookup {
	const void *parent;
	const void *node;
	enum stack_depot_trie_lookup_status status;
	unsigned int matched;
};

struct stack_depot_trie_leaf_update {
	u32 leaf_id;
	const void *leaf;
};

struct stack_depot_trie_publish_prepare {
	int (*fn)(const struct stack_depot_trie_leaf_update *updates,
		  unsigned int nr_updates, void *ctx);
	void *ctx;
};

#define STACK_DEPOT_TRIE_MAX_LEAF_UPDATES 2
#define STACK_DEPOT_TRIE_MAX_NODE_SLOTS (CONFIG_STACKDEPOT_MAX_FRAMES + 1)
#define STACK_DEPOT_TRIE_MAX_CHILD_SLOTS CONFIG_STACKDEPOT_MAX_FRAMES

struct stack_depot_trie_side_checkpoint {
	u32 leaf_id;
	const void *old_leaf;
};

struct stack_depot_trie_side_prepare {
	struct stack_depot_trie_side_checkpoint updates[STACK_DEPOT_TRIE_MAX_LEAF_UPDATES];
	unsigned int nr_updates;
};

struct stack_depot_trie_pool_mark {
	void *pool;
	size_t prev_offset;
	size_t offset;
	size_t size;
	unsigned int pool_index;
	bool added_pool;
};

struct stack_depot_trie_pool_request {
	struct stack_depot_trie_node_slot *node_slots;
	struct stack_depot_trie_child_array_slot *child_slots;
	void **storage;
	void **prealloc;
	struct stack_depot_trie_pool_mark *mark;
	size_t storage_size;
	unsigned int nr_node_slots;
	unsigned int nr_child_slots;
};

struct stack_depot_trie_alloc_txn {
	struct stack_depot_trie_side_prepare side;
	struct stack_depot_trie_pool_mark pool;
	u32 leaf_id;
};

struct stack_depot_trie_alloc_request {
	struct stack_depot_trie_alloc_txn *txn;
	struct stack_depot_trie_node_slot *node_slots;
	struct stack_depot_trie_child_array_slot *child_slots;
	void **storage;
	void **pool_prealloc;
	void **side_prealloc;
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
	void *storage;
};

#define STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS 9
#define STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE \
	(1U << STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_BITS)

depot_stack_handle_t __stack_depot_trie_handle(u32 leaf_id);
u32 __stack_depot_trie_leaf_id(depot_stack_handle_t handle);
u32 __stack_depot_trie_max_leaf_id(void);

/*
 * Private trie leaf side table. Writers serialize internally; lookup is
 * lockless. Init and destroy are controlled setup/teardown operations and must
 * not race with lookup.
 */
int __stack_depot_trie_side_table_init(gfp_t gfp_flags);
void __stack_depot_trie_side_table_destroy(void);
bool __stack_depot_trie_side_table_prealloc_needed(void);
void *__stack_depot_trie_side_table_prealloc(gfp_t gfp_flags);
void __stack_depot_trie_side_table_free_prealloc(void *prealloc);
u32 __stack_depot_trie_side_table_alloc_id(void **prealloc);
void __stack_depot_trie_side_table_revoke_latest(u32 id);
void __stack_depot_trie_side_table_restore(u32 id, const void *entry);
int __stack_depot_trie_side_table_store(u32 id, const void *entry);
const void *__stack_depot_trie_side_table_lookup(u32 id);
size_t __stack_depot_trie_side_table_entries(void);
size_t __stack_depot_trie_side_table_bytes(void);
size_t __stack_depot_trie_pool_alloc_size(size_t size);
void *__stack_depot_trie_pool_prealloc(gfp_t gfp_flags);
void __stack_depot_trie_pool_free_prealloc(void *prealloc);
int __stack_depot_trie_alloc_prealloc(gfp_t alloc_flags,
				      depot_flags_t depot_flags,
				      void **pool_prealloc,
				      void **side_prealloc);
/*
 * Best-effort current-pool helpers. They never allocate or roll over to a new
 * pool, and they use trylock so constrained contexts fail instead of blocking.
 */
void *
__stack_depot_trie_pool_carve_current(size_t size,
				      struct stack_depot_trie_pool_mark *mark);
bool __stack_depot_trie_pool_try_rollback(const struct stack_depot_trie_pool_mark *mark);
int __stack_depot_trie_pool_carve(struct stack_depot_trie_pool_request *req);
void __stack_depot_trie_alloc_txn_init(struct stack_depot_trie_alloc_txn *txn);
int
__stack_depot_trie_alloc_txn_id(struct stack_depot_trie_alloc_txn *txn, void **prealloc);
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
				  void **side_prealloc,
				  struct stack_depot_trie_alloc_request *req);
int __stack_depot_trie_workspace_plan(const struct stack_depot_trie_root *root,
				      const unsigned long *entries,
				      unsigned int nr_entries, void **pool_prealloc,
				      void **side_prealloc,
				      struct stack_depot_trie_alloc_workspace *workspace);
int __stack_depot_trie_workspace_insert(struct stack_depot_trie_root *root,
					const unsigned long *entries,
					unsigned int nr_entries, void **pool_prealloc,
					void **side_prealloc,
					struct stack_depot_trie_alloc_workspace *workspace,
					const void **tail, u32 *leaf_id);
depot_stack_handle_t
__stack_depot_trie_save_miss(struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries,
			     gfp_t alloc_flags, depot_flags_t depot_flags,
			     struct stack_depot_trie_alloc_workspace *workspace);
depot_stack_handle_t
__stack_depot_trie_save(struct stack_depot_trie_root *root,
			const unsigned long *entries, unsigned int nr_entries,
			gfp_t alloc_flags, depot_flags_t depot_flags,
			struct stack_depot_trie_alloc_workspace *workspace);
int __stack_depot_trie_alloc_txn_reserve(struct stack_depot_trie_alloc_request *req);
u32 __stack_depot_trie_alloc_txn_commit(struct stack_depot_trie_alloc_txn *txn);
int
__stack_depot_trie_alloc_txn_insert(struct stack_depot_trie_root *root,
				    struct stack_depot_trie_alloc_request *req,
				    const unsigned long *entries,
				    unsigned int nr_entries, u32 *scratch,
				    unsigned int nr_scratch, const void **tail,
				    u32 *leaf_id);
void __stack_depot_trie_alloc_txn_rollback(struct stack_depot_trie_alloc_txn *txn);
void __stack_depot_trie_side_prepare_init(struct stack_depot_trie_side_prepare *state);
int
__stack_depot_trie_side_prepare(const struct stack_depot_trie_leaf_update *updates,
				unsigned int nr_updates, void *ctx);
void __stack_depot_trie_side_rollback(struct stack_depot_trie_side_prepare *state);
bool __stack_depot_frame_try_compress(unsigned long frame, u8 *prefix_id,
				      u32 *low);
bool __stack_depot_frame_decompress(u8 prefix_id, u32 low,
				    unsigned long *frame);
int __stack_depot_frame_run_init(const unsigned long *entries,
				 unsigned int nr_entries,
				 struct stack_depot_frame_run *run);
int __stack_depot_frame_run_write(const struct stack_depot_frame_run *run,
				  const unsigned long *entries, void *dst,
				  size_t dst_size, u32 *scratch,
				  unsigned int nr_scratch);
int __stack_depot_frame_run_read(const struct stack_depot_frame_run *run,
				 const void *src, size_t src_size,
				 unsigned long *entries, unsigned int max_entries,
				 unsigned long *scratch,
				 unsigned int nr_scratch);
size_t __stack_depot_trie_node_size(const struct stack_depot_frame_run *run);
int __stack_depot_trie_node_init(void *storage, size_t storage_size,
				 const void *parent, u32 leaf_id,
				 const unsigned long *entries,
				 unsigned int nr_entries, u32 *scratch,
				 unsigned int nr_scratch);
int __stack_depot_trie_node_init_slice(void *storage, size_t storage_size,
				       const void *parent, u32 leaf_id,
				       const void *src_node, unsigned int start,
				       unsigned int nr_entries);
unsigned int __stack_depot_trie_node_match(const void *node,
					   const unsigned long *entries,
					   unsigned int nr_entries);
int __stack_depot_trie_append_chain(const void *parent, u32 leaf_id,
				    const unsigned long *entries,
				    unsigned int nr_entries,
				    const struct stack_depot_trie_node_slot *node_slots,
				    unsigned int nr_node_slots,
				    const struct stack_depot_trie_child_array_slot *child_slots,
				    unsigned int nr_child_slots, u32 *scratch,
				    unsigned int nr_scratch, const void **head,
				    const void **tail, unsigned int *nr_used);
int __stack_depot_trie_publish_append(struct stack_depot_trie_root *root,
				      void *parent, const void *head,
				      void *new_storage, size_t new_storage_size);
int __stack_depot_trie_lookup_step(const struct stack_depot_trie_root *root,
				   const void *parent, const unsigned long *entries,
				   unsigned int nr_entries,
				   struct stack_depot_trie_lookup *lookup);
const void *
__stack_depot_trie_find_leaf(const struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries);
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
				     unsigned int *nr_used);
int
__stack_depot_trie_insert_append_prepare(struct stack_depot_trie_root *root,
					 void *parent, u32 leaf_id,
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
					 const void **tail, unsigned int *nr_used);
int
__stack_depot_trie_insert_plan(const struct stack_depot_trie_root *root,
			       const void *parent, const unsigned long *entries,
			       unsigned int nr_entries,
			       struct stack_depot_trie_node_slot *node_slots,
			       unsigned int nr_node_slots,
			       struct stack_depot_trie_child_array_slot *child_slots,
			       unsigned int nr_child_slots, size_t *new_storage_size,
			       unsigned int *nr_used, unsigned int *nr_child_used);
unsigned int __stack_depot_trie_fetch_into(const void *leaf,
					   unsigned long *entries,
					   unsigned int max_entries);
unsigned int __stack_depot_trie_fetch_handle_into(depot_stack_handle_t handle,
						  unsigned long *entries,
						  unsigned int max_entries);
size_t __stack_depot_trie_child_array_size(unsigned int nr_children);
int __stack_depot_trie_child_array_init(void *storage, size_t storage_size,
					const void * const *children,
					unsigned int nr_children);
int __stack_depot_trie_split_child_array_init(void *storage, size_t storage_size,
					      const void *old_tail,
					      const void *new_head);
int __stack_depot_trie_split_tail_plan(const unsigned long *entries,
				       unsigned int nr_entries,
				       const struct stack_depot_trie_node_slot *node_slots,
				       unsigned int nr_node_slots,
				       const struct stack_depot_trie_child_array_slot *child_slots,
				       unsigned int nr_child_slots,
				       unsigned int *nr_runs);
int __stack_depot_trie_split_precheck(struct stack_depot_trie_root *root,
				      const void *parent,
				      const struct stack_depot_trie_node_slot *node_slots,
				      unsigned int nr_node_slots,
				      const struct stack_depot_trie_child_array_slot *child_slots,
				      unsigned int nr_child_slots,
				      void *new_storage, size_t new_storage_size);
int __stack_depot_trie_split_subtree(const void *child, unsigned int matched,
				     u32 leaf_id, const unsigned long *entries,
				     unsigned int nr_entries,
				     const struct stack_depot_trie_node_slot *node_slots,
				     unsigned int nr_node_slots,
				     const struct stack_depot_trie_child_array_slot *child_slots,
				     unsigned int nr_child_slots, u32 *scratch,
				     unsigned int nr_scratch, const void **prefix,
				     const void **tail, unsigned int *nr_used);
const void *__stack_depot_trie_child_array_find(const void *storage,
						unsigned long frame);
int __stack_depot_trie_child_array_insert(const void *old_storage,
					  const void *child, void *new_storage,
					  size_t new_storage_size);

#endif /* _STACKDEPOT_INTERNAL_H */
