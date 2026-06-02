/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _STACKDEPOT_INTERNAL_H
#define _STACKDEPOT_INTERNAL_H

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
	enum stack_depot_frame_mode mode;
	u8 prefix_id;
	unsigned int nr_entries;
	size_t bytes;
};

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
	enum stack_depot_trie_lookup_status status;
	const void *parent;
	const void *node;
	unsigned int matched;
};

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
unsigned int __stack_depot_trie_fetch_into(const void *leaf,
					   unsigned long *entries,
					   unsigned int max_entries,
					   unsigned long *scratch,
					   unsigned int nr_scratch);
size_t __stack_depot_trie_child_array_size(unsigned int nr_children);
int __stack_depot_trie_child_array_init(void *storage, size_t storage_size,
					const void * const *children,
					unsigned int nr_children);
const void *__stack_depot_trie_child_array_find(const void *storage,
						unsigned long frame);
int __stack_depot_trie_child_array_insert(const void *old_storage,
					  const void *child, void *new_storage,
					  size_t new_storage_size);

#endif /* _STACKDEPOT_INTERNAL_H */
