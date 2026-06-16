// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/stackdepot.h>
#include <linux/stacktrace.h>
#include <linux/string.h>

#include "../stackdepot_internal.h"

#ifdef CONFIG_ARM64
#include <asm/stackdepot.h>
#endif

static int
frame_run_init(const unsigned long *entries, unsigned int nr_entries,
	       struct stack_depot_frame_run *run)
{
	return __stack_depot_frame_run_init(entries, nr_entries, run);
}

static int frame_run_write(const struct stack_depot_frame_run *run,
			   const unsigned long *entries, void *dst, size_t dst_size,
			   u32 *scratch, unsigned int nr_scratch)
{
	return __stack_depot_frame_run_write(run, entries, dst, dst_size,
						  scratch, nr_scratch);
}

static int frame_run_read(const struct stack_depot_frame_run *run,
			  const void *src, size_t src_size,
			  unsigned long *entries, unsigned int max_entries,
			  unsigned long *scratch, unsigned int nr_scratch)
{
	return __stack_depot_frame_run_read(run, src, src_size, entries,
						  max_entries, scratch, nr_scratch);
}

static int tnode_init(void *storage, size_t storage_size, const void *parent,
		      u32 leaf_id, const unsigned long *entries,
		      unsigned int nr_entries, u32 *scratch,
		      unsigned int nr_scratch)
{
	return __stack_depot_trie_node_init(storage, storage_size, parent, leaf_id,
						 entries, nr_entries, scratch,
						 nr_scratch);
}

static int
tnode_init_slice(void *storage, size_t storage_size, const void *parent,
		 u32 leaf_id, const void *src_node, unsigned int start,
		 unsigned int nr_entries)
{
	return __stack_depot_trie_node_init_slice(storage, storage_size, parent,
					       leaf_id, src_node, start, nr_entries);
}

static unsigned int tfetch(const void *leaf, unsigned long *entries,
			   unsigned int max_entries)
{
	return __stack_depot_trie_fetch_into(leaf, entries, max_entries);
}

static unsigned int tmatch(const void *node, const unsigned long *entries,
			   unsigned int nr_entries)
{
	return __stack_depot_trie_node_match(node, entries, nr_entries);
}

static int
append_chain(const void *parent, u32 leaf_id, const unsigned long *entries,
	     unsigned int nr_entries,
	     const struct stack_depot_trie_node_slot *node_slots,
	     unsigned int nr_node_slots,
	     const struct stack_depot_trie_child_array_slot *child_slots,
	     unsigned int nr_child_slots, u32 *scratch, unsigned int nr_scratch,
	     const void **head, const void **tail, unsigned int *nr_used)
{
	return __stack_depot_trie_append_chain(parent, leaf_id, entries,
			nr_entries, node_slots, nr_node_slots, child_slots,
			nr_child_slots, scratch, nr_scratch, head, tail, nr_used);
}

static int publish_append(struct stack_depot_trie_root *root, void *parent,
			  const void *head, void *storage, size_t storage_size)
{
	return __stack_depot_trie_publish_append(root, parent, head, storage,
						  storage_size);
}

static int lookup_step(const struct stack_depot_trie_root *root,
		       const void *parent, const unsigned long *entries,
		       unsigned int nr_entries,
		       struct stack_depot_trie_lookup *lookup)
{
	return __stack_depot_trie_lookup_step(root, parent, entries, nr_entries,
				      lookup);
}

static const void *find_leaf(const struct stack_depot_trie_root *root,
			     const unsigned long *entries, unsigned int nr_entries)
{
	return __stack_depot_trie_find_leaf(root, entries, nr_entries);
}

static int insert_append(struct stack_depot_trie_root *root, void *parent,
			 u32 leaf_id, const unsigned long *entries,
			 unsigned int nr_entries,
			 const struct stack_depot_trie_node_slot *node_slots,
			 unsigned int nr_node_slots,
			 const struct stack_depot_trie_child_array_slot *child_slots,
			 unsigned int nr_child_slots, u32 *scratch,
			 unsigned int nr_scratch, void *storage, size_t storage_size,
			 const void **tail, unsigned int *nr_used)
{
	return __stack_depot_trie_insert_append(root, parent, leaf_id, entries,
			nr_entries, node_slots, nr_node_slots, child_slots,
			nr_child_slots, scratch, nr_scratch, storage,
			storage_size, tail, nr_used);
}

static int
insert_append_prepare(struct stack_depot_trie_root *root, void *parent,
		      u32 leaf_id, const unsigned long *entries,
		      unsigned int nr_entries,
		      const struct stack_depot_trie_node_slot *node_slots,
		      unsigned int nr_node_slots,
		      const struct stack_depot_trie_child_array_slot *child_slots,
		      unsigned int nr_child_slots, u32 *scratch,
		      unsigned int nr_scratch, void *storage, size_t storage_size,
		      const struct stack_depot_trie_publish_prepare *prepare,
		      const void **tail, unsigned int *nr_used)
{
	return __stack_depot_trie_insert_append_prepare(root, parent, leaf_id,
						       entries, nr_entries, node_slots,
						       nr_node_slots, child_slots,
						       nr_child_slots, scratch,
						       nr_scratch, storage,
						       storage_size, prepare, tail,
						       nr_used);
}

static int insert_plan(const struct stack_depot_trie_root *root,
		       const void *parent, const unsigned long *entries,
		       unsigned int nr_entries,
		       struct stack_depot_trie_node_slot *node_slots,
		       unsigned int nr_node_slots,
		       struct stack_depot_trie_child_array_slot *child_slots,
		       unsigned int nr_child_slots, size_t *new_storage_size,
		       unsigned int *nr_used, unsigned int *nr_child_used)
{
	return __stack_depot_trie_insert_plan(root, parent, entries, nr_entries,
					      node_slots, nr_node_slots,
					      child_slots, nr_child_slots,
					      new_storage_size, nr_used,
					      nr_child_used);
}

#define STACKDEPOT_TRIE_PREPARE_MAX_UPDATES 2

struct stackdepot_trie_prepare_ctx {
	struct kunit *test;
	const struct stack_depot_trie_child_array **visible;
	const struct stack_depot_trie_child_array *expected_visible;
	const void *expected_leaf[STACKDEPOT_TRIE_PREPARE_MAX_UPDATES];
	u32 expected_leaf_id[STACKDEPOT_TRIE_PREPARE_MAX_UPDATES];
	unsigned int nr_expected;
	unsigned int calls;
	int ret;
};

static int
stackdepot_trie_prepare(const struct stack_depot_trie_leaf_update *updates,
			unsigned int nr_updates, void *data)
{
	struct stackdepot_trie_prepare_ctx *ctx = data;
	unsigned int i;

	ctx->calls++;
	KUNIT_EXPECT_NOT_NULL(ctx->test, updates);
	if (!updates)
		return -EINVAL;
	KUNIT_EXPECT_EQ(ctx->test, nr_updates, ctx->nr_expected);
	for (i = 0; i < nr_updates && i < ctx->nr_expected; i++) {
		KUNIT_EXPECT_EQ(ctx->test, updates[i].leaf_id,
				ctx->expected_leaf_id[i]);
		KUNIT_EXPECT_PTR_EQ(ctx->test, updates[i].leaf,
				    ctx->expected_leaf[i]);
	}
	if (ctx->visible)
		KUNIT_EXPECT_PTR_EQ(ctx->test, *ctx->visible,
				    ctx->expected_visible);

	return ctx->ret;
}

static int split_subtree(const void *child, unsigned int matched, u32 leaf_id,
			 const unsigned long *entries, unsigned int nr_entries,
			 const struct stack_depot_trie_node_slot *node_slots,
			 unsigned int nr_node_slots,
			 const struct stack_depot_trie_child_array_slot *child_slots,
			 unsigned int nr_child_slots, u32 *scratch,
			 unsigned int nr_scratch, const void **prefix,
			 const void **tail, unsigned int *nr_used)
{
	return __stack_depot_trie_split_subtree(child, matched, leaf_id, entries,
			nr_entries, node_slots, nr_node_slots, child_slots,
			nr_child_slots, scratch, nr_scratch, prefix, tail, nr_used);
}

static void
trie_node_slot_alloc(struct kunit *test,
		     struct stack_depot_trie_node_slot *slot,
		     const unsigned long *entries, unsigned int nr_entries)
{
	struct stack_depot_frame_run run;

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, nr_entries, &run), 0);
	KUNIT_ASSERT_EQ(test, run.nr_entries, nr_entries);
	slot->size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, slot->size, (size_t)0);
	slot->node = kunit_kzalloc(test, slot->size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slot->node);
}

static int child_array_init(void *storage, size_t storage_size,
			    const void * const *children, unsigned int nr_children)
{
	return __stack_depot_trie_child_array_init(storage, storage_size, children,
						       nr_children);
}

static int split_child_array_init(void *storage, size_t storage_size,
				  const void *old_tail, const void *new_head)
{
	return __stack_depot_trie_split_child_array_init(storage, storage_size,
						     old_tail, new_head);
}

static int split_tail_plan(const unsigned long *entries, unsigned int nr_entries,
			   const struct stack_depot_trie_node_slot *node_slots,
			   unsigned int nr_node_slots,
			   const struct stack_depot_trie_child_array_slot *child_slots,
			   unsigned int nr_child_slots, unsigned int *nr_runs)
{
	return __stack_depot_trie_split_tail_plan(entries, nr_entries, node_slots,
					       nr_node_slots, child_slots,
					       nr_child_slots, nr_runs);
}

static int split_precheck(struct stack_depot_trie_root *root, const void *parent,
			  const struct stack_depot_trie_node_slot *node_slots,
			  unsigned int nr_node_slots,
			  const struct stack_depot_trie_child_array_slot *child_slots,
			  unsigned int nr_child_slots, void *new_storage,
			  size_t new_storage_size)
{
	return __stack_depot_trie_split_precheck(root, parent, node_slots,
			nr_node_slots, child_slots, nr_child_slots,
			new_storage, new_storage_size);
}

static int child_array_insert(const void *old_storage, const void *child,
			      void *new_storage, size_t new_storage_size)
{
	return __stack_depot_trie_child_array_insert(old_storage, child,
						 new_storage, new_storage_size);
}

static const void *child_array_find(const void *storage, unsigned long frame)
{
	return __stack_depot_trie_child_array_find(storage, frame);
}

static void
trie_node_alloc(struct kunit *test, const unsigned long *entries,
		unsigned int nr_entries, const void *parent, u32 leaf_id,
		void **node)
{
	u32 write_scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	struct stack_depot_frame_run run;
	size_t size;
	int ret;

	/* This helper allocates one trie node, so @entries must form one run. */
	KUNIT_ASSERT_EQ(test, frame_run_init(entries, nr_entries, &run), 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	*node = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, *node);
	ret = tnode_init(*node, size, parent, leaf_id, entries, nr_entries,
			 write_scratch, ARRAY_SIZE(write_scratch));
	KUNIT_ASSERT_EQ(test, ret, 0);
}

static void trie_fill_raw_entries(unsigned long *entries, unsigned int nr_entries,
				  unsigned long base)
{
	unsigned int i;

	for (i = 0; i < nr_entries; i++)
		entries[i] = base + i * 0x10UL;
}

static void stackdepot_fetch_into_roundtrip(struct kunit *test)
{
	unsigned long entries[] = {
		0x1234567800010000UL,
		0x1234567800020000UL,
		0x1234567800030000UL,
	};
	unsigned long exact[ARRAY_SIZE(entries)] = {};
	unsigned long fetched[ARRAY_SIZE(entries) + 1] = {
		[ARRAY_SIZE(entries)] = 0xa5a5a5a5a5a5a5a5UL,
	};
	unsigned long expected_tail = fetched[ARRAY_SIZE(entries)];
	depot_stack_handle_t handle;
	unsigned int nr_entries;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);

	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);

	nr_entries =
		stack_depot_fetch_into(handle, exact, ARRAY_SIZE(exact));
	KUNIT_EXPECT_EQ(test, nr_entries, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, exact, entries, sizeof(entries));

	nr_entries =
		stack_depot_fetch_into(handle, fetched, ARRAY_SIZE(fetched));
	KUNIT_EXPECT_EQ(test, nr_entries, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, fetched, entries, sizeof(entries));
	KUNIT_EXPECT_EQ(test, fetched[ARRAY_SIZE(entries)], expected_tail);
}

static void stackdepot_fetch_into_rejects_bad_inputs(struct kunit *test)
{
	unsigned long entries[] = {
		0x1234567800110000UL,
		0x1234567800120000UL,
		0x1234567800130000UL,
	};
	unsigned long fetched[ARRAY_SIZE(entries)] = {
		0xa1a1a1a1a1a1a1a1UL,
		0xb2b2b2b2b2b2b2b2UL,
		0xc3c3c3c3c3c3c3c3UL,
	};
	unsigned long expected[ARRAY_SIZE(fetched)];
	depot_stack_handle_t handle;
	unsigned int nr_entries;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);

	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);
	memcpy(expected, fetched, sizeof(expected));

	nr_entries = stack_depot_fetch_into(0, fetched, ARRAY_SIZE(fetched));
	KUNIT_EXPECT_EQ(test, nr_entries, 0);
	KUNIT_EXPECT_MEMEQ(test, fetched, expected, sizeof(expected));

	nr_entries = stack_depot_fetch_into(0, NULL, 0);
	KUNIT_EXPECT_EQ(test, nr_entries, 0);
	/* No buffer is supplied for this invalid-input combination. */

	nr_entries = stack_depot_fetch_into(handle, NULL, ARRAY_SIZE(fetched));
	KUNIT_EXPECT_EQ(test, nr_entries, 0);
	KUNIT_EXPECT_MEMEQ(test, fetched, expected, sizeof(expected));

	nr_entries = stack_depot_fetch_into(handle, fetched, 0);
	KUNIT_EXPECT_EQ(test, nr_entries, 0);
	KUNIT_EXPECT_MEMEQ(test, fetched, expected, sizeof(expected));

	nr_entries = stack_depot_fetch_into(handle, fetched,
					    ARRAY_SIZE(fetched) - 1);
	KUNIT_EXPECT_EQ(test, nr_entries, 0);
	KUNIT_EXPECT_MEMEQ(test, fetched, expected, sizeof(expected));
}

static void stackdepot_count_helpers(struct kunit *test)
{
	unsigned long entries[] = {
		0x1234567800210000UL,
		0x1234567800220000UL,
		0x1234567800230000UL,
	};
	unsigned long zero_entries[] = {
		0x1234567800310000UL,
		0x1234567800320000UL,
		0x1234567800330000UL,
	};
	unsigned long zeroed_entries[] = {
		0x1234567800610000UL,
		0x1234567800620000UL,
		0x1234567800630000UL,
	};
	unsigned long seeded_entries[] = {
		0x1234567800410000UL,
		0x1234567800420000UL,
		0x1234567800430000UL,
	};
	unsigned long max_entries[] = {
		0x1234567800510000UL,
		0x1234567800520000UL,
		0x1234567800530000UL,
	};
	depot_stack_handle_t handle;
	depot_stack_handle_t second_handle;
	depot_stack_handle_t seeded_handle;
	depot_stack_handle_t max_handle;
	depot_stack_handle_t zeroed_handle;
	unsigned int zeroed_nr = ARRAY_SIZE(zeroed_entries);
	bool new_count;
	unsigned int count;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);

	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(0, &count));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(0, NULL));
	__stack_depot_set_count(0, 1);
	__stack_depot_set_count(0, 0);
	__stack_depot_set_count(0, INT_MAX);
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(0, 1, &new_count));
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_inc_count(0, INT_MAX - 2, &new_count));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(0, 1));

	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);

	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_inc_count(handle, INT_MAX, &new_count));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(handle, 1));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(handle, &count));

	max_handle = stack_depot_save(max_entries, ARRAY_SIZE(max_entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, max_handle, (depot_stack_handle_t)0);
	new_count = false;
	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_inc_count(max_handle, INT_MAX - 1,
						  &new_count));
	KUNIT_EXPECT_TRUE(test, new_count);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(max_handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX);
	new_count = true;
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_inc_count(max_handle, 1, &new_count));
	KUNIT_EXPECT_FALSE(test, new_count);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(max_handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX);
	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_dec_count_and_test(max_handle, INT_MAX));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(max_handle, &count));

	new_count = false;
	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(handle, 2, &new_count));
	KUNIT_EXPECT_TRUE(test, new_count);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 3);

	/* Already-counted records increment without needing a list marker. */
	new_count = true;
	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(handle, 4, &new_count));
	KUNIT_EXPECT_FALSE(test, new_count);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 7);

	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(handle, 5));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(handle, 3));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	__stack_depot_set_count(handle, 0);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	__stack_depot_set_count(handle, INT_MAX - 1);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX - 1);
	__stack_depot_set_count(handle, 2);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	__stack_depot_set_count(handle, INT_MAX);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX);
	__stack_depot_set_count(handle, 2);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	__stack_depot_set_count(handle, 6);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 6);
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_inc_count(handle, INT_MAX, &new_count));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 6);

	second_handle = stack_depot_save(zero_entries, ARRAY_SIZE(zero_entries),
					 GFP_KERNEL);
	KUNIT_ASSERT_NE(test, second_handle, (depot_stack_handle_t)0);
	new_count = false;
	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_inc_count(second_handle, 1, &new_count));
	KUNIT_EXPECT_TRUE(test, new_count);
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_dec_count_and_test(second_handle, 1));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(second_handle, &count));
	KUNIT_EXPECT_EQ(test, count, 1);

	seeded_handle = stack_depot_save(seeded_entries, ARRAY_SIZE(seeded_entries),
					 GFP_KERNEL);
	KUNIT_ASSERT_NE(test, seeded_handle, (depot_stack_handle_t)0);
	__stack_depot_set_count(seeded_handle, 3);
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_dec_count_and_test(seeded_handle, 1));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(seeded_handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);

	zeroed_handle = stack_depot_save(zeroed_entries, zeroed_nr, GFP_KERNEL);
	KUNIT_ASSERT_NE(test, zeroed_handle, (depot_stack_handle_t)0);
	__stack_depot_set_count(zeroed_handle, 3);
	KUNIT_EXPECT_TRUE(test, __stack_depot_dec_count_and_test(zeroed_handle, 3));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(zeroed_handle, 1));
}

static void stackdepot_trie_handle_namespace(struct kunit *test)
{
	unsigned long entries[] = {
		0x1234567800710000UL,
		0x1234567800720000UL,
		0x1234567800730000UL,
	};
	depot_stack_handle_t boundary_handle;
	depot_stack_handle_t extra_only;
	depot_stack_handle_t hash_handle;
	depot_stack_handle_t tagged;
	depot_stack_handle_t trie;
	u32 boundary_id;
	u32 max_id;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);

	trie = __stack_depot_trie_handle(1);
	hash_handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_EXPECT_NE(test, hash_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(hash_handle), 0U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_handle(0), (depot_stack_handle_t)0);
	extra_only = (depot_stack_handle_t)7 <<
		(DEPOT_HANDLE_BITS - STACK_DEPOT_EXTRA_BITS);
	KUNIT_EXPECT_EQ(test, stack_depot_set_extra_bits(extra_only, 1),
			(depot_stack_handle_t)0);

	if (!trie) {
		KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(0), 0U);
		return;
	}

	boundary_id = (1U << DEPOT_OFFSET_BITS) + 2;
	max_id = __stack_depot_trie_max_leaf_id();
	boundary_handle = __stack_depot_trie_handle(boundary_id);
	tagged = stack_depot_set_extra_bits(trie, 7);

	KUNIT_EXPECT_NE(test, boundary_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(trie), 1U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(tagged), 1U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(boundary_handle),
			boundary_id);
	KUNIT_EXPECT_NE(test, max_id, 0U);
	KUNIT_EXPECT_NE(test, __stack_depot_trie_handle(max_id),
			(depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_handle(max_id + 1),
			(depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_handle(U32_MAX),
			(depot_stack_handle_t)0);
}

static void stackdepot_trie_disable_action(void *data)
{
	__stack_depot_trie_set_enabled(false);
}

static void stackdepot_trie_add_disable_action(struct kunit *test)
{
	int ret;

	ret = kunit_add_action_or_reset(test, stackdepot_trie_disable_action, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
}

static void stackdepot_trie_feature_flag(struct kunit *test)
{
	stackdepot_trie_add_disable_action(test);

	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_enabled());

	__stack_depot_trie_set_enabled(true);
	KUNIT_EXPECT_TRUE(test, __stack_depot_trie_enabled());

	__stack_depot_trie_set_enabled(true);
	KUNIT_EXPECT_TRUE(test, __stack_depot_trie_enabled());

	__stack_depot_trie_set_enabled(false);
	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_enabled());
}

static void stackdepot_trie_late_init(struct kunit *test)
{
	stackdepot_trie_add_disable_action(test);
	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_ready());
	if (!__stack_depot_trie_max_leaf_id())
		kunit_skip(test, "trie handle namespace unavailable");

	__stack_depot_trie_set_enabled(true);
	KUNIT_EXPECT_EQ(test, stack_depot_init(), 0);
	KUNIT_EXPECT_TRUE(test, __stack_depot_trie_ready());
}

static void stackdepot_trie_side_table_destroy_action(void *data)
{
	__stack_depot_trie_side_table_destroy();
}

static void stackdepot_trie_side_table_init_or_skip(struct kunit *test)
{
	int ret;

	ret = __stack_depot_trie_side_table_init(GFP_KERNEL);
	if (ret == -EINVAL && !__stack_depot_trie_max_leaf_id())
		kunit_skip(test, "trie handle namespace unavailable");
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = kunit_add_action_or_reset(test, stackdepot_trie_side_table_destroy_action, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
}

static void
stackdepot_trie_side_table_prealloc_or_fail(struct kunit *test,
					    struct stack_depot_trie_side_prealloc *prealloc)
{
	int ret;

	ret = __stack_depot_trie_side_table_prealloc(GFP_KERNEL, prealloc);
	KUNIT_ASSERT_EQ(test, ret, 0);
}

static u32 stackdepot_trie_side_table_alloc(struct kunit *test)
{
	struct stack_depot_trie_side_prealloc prealloc = {};
	u32 id;

	if (__stack_depot_trie_side_table_prealloc_needed()) {
		stackdepot_trie_side_table_prealloc_or_fail(test, &prealloc);
		KUNIT_ASSERT_TRUE(test, prealloc.dir || prealloc.chunk);
	}

	id = __stack_depot_trie_side_table_alloc_id(&prealloc);
	__stack_depot_trie_side_table_free_prealloc(&prealloc);
	return id;
}

static void stackdepot_trie_side_table_destroy_uninit(struct kunit *test)
{
	__stack_depot_trie_side_table_destroy();
	KUNIT_SUCCEED(test);
}

static void stackdepot_trie_side_table_alloc_store_lookup(struct kunit *test)
{
	const void *entry1 = (const void *)0x1111UL;
	const void *entry2 = (const void *)0x2222UL;
	u32 id1;
	u32 id2;

	stackdepot_trie_side_table_init_or_skip(test);
	id1 = stackdepot_trie_side_table_alloc(test);
	id2 = stackdepot_trie_side_table_alloc(test);

	KUNIT_ASSERT_EQ(test, id1, 1U);
	KUNIT_ASSERT_EQ(test, id2, 2U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_store(id1, entry1), 0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_store(id2, entry2), 0);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id1), entry1);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id2), entry2);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 2UL);
}

static void stackdepot_trie_side_table_rejects_invalid_ids(struct kunit *test)
{
	int ret;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(0));

	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(id + 1));
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_store(id, NULL), -EINVAL);
	ret = __stack_depot_trie_side_table_store(id + 1, (const void *)0x1UL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_side_table_revoke_latest(struct kunit *test)
{
	const void *entry = (const void *)0xaaaaUL;
	size_t bytes;
	int ret;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	ret = __stack_depot_trie_side_table_store(id, entry);
	KUNIT_ASSERT_EQ(test, ret, 0);
	bytes = __stack_depot_trie_side_table_bytes();
	KUNIT_EXPECT_GT(test, bytes, 0UL);

	__stack_depot_trie_side_table_revoke_latest(id);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_bytes(), bytes);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(id));
}

static void stackdepot_trie_side_table_revoke_keeps_chunk(struct kunit *test)
{
	const void *entry1 = (const void *)0x1111UL;
	const void *entry2 = (const void *)0x2222UL;
	size_t bytes;
	u32 id1;
	u32 id2;

	stackdepot_trie_side_table_init_or_skip(test);
	id1 = stackdepot_trie_side_table_alloc(test);
	id2 = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id1, 1U);
	KUNIT_ASSERT_EQ(test, id2, 2U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id1, entry1), 0);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id2, entry2), 0);
	bytes = __stack_depot_trie_side_table_bytes();

	__stack_depot_trie_side_table_revoke_latest(id2);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_bytes(), bytes);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id1), entry1);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(id2));
}

static void stackdepot_trie_side_table_restore(struct kunit *test)
{
	const void *entry1 = (const void *)0xaaaaUL;
	const void *entry2 = (const void *)0xbbbbUL;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id, entry1), 0);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id, entry2), 0);

	__stack_depot_trie_side_table_restore(id, entry1);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id), entry1);
	__stack_depot_trie_side_table_restore(id, NULL);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(id));
}

static void stackdepot_trie_side_table_chunk_boundary(struct kunit *test)
{
	struct stack_depot_trie_side_prealloc prealloc = {};
	u32 id = 0;
	u32 i;

	stackdepot_trie_side_table_init_or_skip(test);
	for (i = 0; i < STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE; i++)
		id = stackdepot_trie_side_table_alloc(test);

	KUNIT_ASSERT_EQ(test, id, STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_side_table_prealloc_needed());
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_alloc_id(NULL), 0U);

	stackdepot_trie_side_table_prealloc_or_fail(test, &prealloc);
	KUNIT_ASSERT_NOT_NULL(test, prealloc.chunk);
	id = __stack_depot_trie_side_table_alloc_id(&prealloc);
	KUNIT_EXPECT_NULL(test, prealloc.dir);
	KUNIT_EXPECT_NULL(test, prealloc.chunk);
	KUNIT_EXPECT_EQ(test, id, STACK_DEPOT_TRIE_SIDE_TABLE_CHUNK_SIZE + 1);
}

static void stackdepot_trie_side_table_bytes(struct kunit *test)
{
	struct stack_depot_trie_side_prealloc prealloc = {};
	size_t before;
	size_t after;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	before = __stack_depot_trie_side_table_bytes();
	KUNIT_EXPECT_GT(test, before, 0UL);
	stackdepot_trie_side_table_prealloc_or_fail(test, &prealloc);
	KUNIT_ASSERT_TRUE(test, prealloc.dir || prealloc.chunk);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_bytes(), before);

	id = __stack_depot_trie_side_table_alloc_id(&prealloc);
	KUNIT_EXPECT_NULL(test, prealloc.dir);
	KUNIT_EXPECT_NULL(test, prealloc.chunk);
	KUNIT_ASSERT_EQ(test, id, 1U);
	after = __stack_depot_trie_side_table_bytes();
	KUNIT_EXPECT_GT(test, after, before);
}

static void stackdepot_trie_side_prepare_updates(struct kunit *test)
{
	struct stack_depot_trie_side_prepare state;
	struct stack_depot_trie_leaf_update updates[2];
	const void *old1 = (const void *)0x1111UL;
	const void *old2 = (const void *)0x2222UL;
	const void *new1 = (const void *)0xaaaaUL;
	const void *new2 = (const void *)0xbbbbUL;
	int ret;
	u32 id1;
	u32 id2;

	stackdepot_trie_side_table_init_or_skip(test);
	id1 = stackdepot_trie_side_table_alloc(test);
	id2 = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id1, 1U);
	KUNIT_ASSERT_EQ(test, id2, 2U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id1, old1), 0);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id2, old2), 0);
	updates[0].leaf_id = id1;
	updates[0].leaf = new1;
	updates[1].leaf_id = id2;
	updates[1].leaf = new2;

	__stack_depot_trie_side_prepare_init(&state);
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &state);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.nr_updates, (unsigned int)ARRAY_SIZE(updates));
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id1), new1);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id2), new2);

	__stack_depot_trie_side_rollback(&state);
	KUNIT_EXPECT_EQ(test, state.nr_updates, 0U);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id1), old1);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id2), old2);
}

static void stackdepot_trie_side_prepare_failure(struct kunit *test)
{
	struct stack_depot_trie_side_prepare state;
	struct stack_depot_trie_leaf_update updates[2];
	const void *old1 = (const void *)0x1111UL;
	const void *new1 = (const void *)0xaaaaUL;
	int ret;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id, old1), 0);
	updates[0].leaf_id = id;
	updates[0].leaf = new1;
	updates[1].leaf_id = id + 1;
	updates[1].leaf = (const void *)0xbbbbUL;

	__stack_depot_trie_side_prepare_init(&state);
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &state);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, state.nr_updates, 0U);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id), old1);
}

static void stackdepot_trie_side_prepare_duplicate_id(struct kunit *test)
{
	struct stack_depot_trie_side_prepare state;
	struct stack_depot_trie_leaf_update updates[2];
	const void *old = (const void *)0x1111UL;
	const void *mid = (const void *)0x2222UL;
	const void *new = (const void *)0x3333UL;
	int ret;
	u32 id;

	stackdepot_trie_side_table_init_or_skip(test);
	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id, old), 0);
	updates[0].leaf_id = id;
	updates[0].leaf = mid;
	updates[1].leaf_id = id;
	updates[1].leaf = new;

	__stack_depot_trie_side_prepare_init(&state);
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &state);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id), new);
	__stack_depot_trie_side_rollback(&state);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id), old);
}

static void stackdepot_trie_side_prepare_rejects_extra_update(struct kunit *test)
{
	struct stack_depot_trie_side_prepare state;
	struct stack_depot_trie_leaf_update updates[3];
	const void *old[] = {
		(const void *)0x1111UL,
		(const void *)0x2222UL,
		(const void *)0x3333UL,
	};
	const void *new[] = {
		(const void *)0xaaaaUL,
		(const void *)0xbbbbUL,
		(const void *)0xccccUL,
	};
	u32 id[ARRAY_SIZE(updates)];
	unsigned int i;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	for (i = 0; i < ARRAY_SIZE(updates); i++) {
		id[i] = stackdepot_trie_side_table_alloc(test);
		KUNIT_ASSERT_EQ(test, id[i], i + 1);
		KUNIT_ASSERT_EQ(test,
				__stack_depot_trie_side_table_store(id[i], old[i]),
				0);
		updates[i].leaf_id = id[i];
		updates[i].leaf = new[i];
	}

	__stack_depot_trie_side_prepare_init(&state);
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &state);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, state.nr_updates, 0U);
	for (i = 0; i < ARRAY_SIZE(updates); i++)
		KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id[i]),
				    old[i]);
}

static void stackdepot_trie_side_prepare_rejects_null_leaf(struct kunit *test)
{
	struct stack_depot_trie_side_prepare state;
	struct stack_depot_trie_leaf_update updates[2];
	const void *old1 = (const void *)0x1111UL;
	const void *old2 = (const void *)0x2222UL;
	const void *new1 = (const void *)0xaaaaUL;
	u32 id1;
	u32 id2;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	id1 = stackdepot_trie_side_table_alloc(test);
	id2 = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id1, 1U);
	KUNIT_ASSERT_EQ(test, id2, 2U);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id1, old1), 0);
	KUNIT_ASSERT_EQ(test, __stack_depot_trie_side_table_store(id2, old2), 0);
	updates[0].leaf_id = id1;
	updates[0].leaf = new1;
	updates[1].leaf_id = id2;
	updates[1].leaf = NULL;

	__stack_depot_trie_side_prepare_init(&state);
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &state);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, state.nr_updates, 0U);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id1), old1);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(id2), old2);
}

static void stackdepot_trie_pool_alloc_size(struct kunit *test)
{
	size_t align = 1UL << DEPOT_STACK_ALIGN;

	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(0), 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(1), align);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(sizeof(unsigned long)),
			align);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(align), align);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(align + 1),
			align * 2);
	KUNIT_EXPECT_EQ(test,
			__stack_depot_trie_pool_alloc_size(DEPOT_POOL_SIZE - 1),
			(size_t)DEPOT_POOL_SIZE);
	KUNIT_EXPECT_EQ(test,
			__stack_depot_trie_pool_alloc_size(DEPOT_POOL_SIZE),
			(size_t)DEPOT_POOL_SIZE);
	KUNIT_EXPECT_EQ(test,
			__stack_depot_trie_pool_alloc_size(DEPOT_POOL_SIZE + 1),
			0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_pool_alloc_size(SIZE_MAX), 0UL);
}

static void stackdepot_trie_pool_prealloc(struct kunit *test)
{
	void *prealloc;

	KUNIT_EXPECT_NULL(test, __stack_depot_trie_pool_prealloc(0));
	prealloc = __stack_depot_trie_pool_prealloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, prealloc);
	KUNIT_EXPECT_TRUE(test, IS_ALIGNED((unsigned long)prealloc, PAGE_SIZE));
	__stack_depot_trie_pool_free_prealloc(prealloc);
	__stack_depot_trie_pool_free_prealloc(NULL);
}

static int alloc_prealloc_flags(gfp_t gfp_flags, depot_flags_t depot_flags,
				void **pool_prealloc,
				struct stack_depot_trie_side_prealloc *side_prealloc)
{
	return __stack_depot_trie_alloc_prealloc(gfp_flags, depot_flags,
					      pool_prealloc, side_prealloc);
}

static int alloc_prealloc(gfp_t gfp_flags, void **pool_prealloc,
			  struct stack_depot_trie_side_prealloc *side_prealloc)
{
	return alloc_prealloc_flags(gfp_flags, STACK_DEPOT_FLAG_CAN_ALLOC,
				    pool_prealloc, side_prealloc);
}

static void stackdepot_trie_alloc_prealloc(struct kunit *test)
{
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	void *pool_prealloc = NULL;
	u32 id;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	ret = alloc_prealloc_flags(GFP_NOWAIT, 0, &pool_prealloc, &side_prealloc);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_NULL(test, pool_prealloc);
	KUNIT_EXPECT_NULL(test, side_prealloc.dir);
	KUNIT_EXPECT_NULL(test, side_prealloc.chunk);

	ret = alloc_prealloc(GFP_KERNEL, &pool_prealloc, &side_prealloc);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, side_prealloc.dir || side_prealloc.chunk);
	__stack_depot_trie_pool_free_prealloc(pool_prealloc);
	__stack_depot_trie_side_table_free_prealloc(&side_prealloc);
	pool_prealloc = NULL;

	id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, id, 1U);
	ret = alloc_prealloc(GFP_NOWAIT, &pool_prealloc, &side_prealloc);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, pool_prealloc);
	KUNIT_EXPECT_NULL(test, side_prealloc.dir);
	KUNIT_EXPECT_NULL(test, side_prealloc.chunk);

	pool_prealloc = (void *)0x1111UL;
	ret = alloc_prealloc(GFP_KERNEL, &pool_prealloc, &side_prealloc);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_pool_seed_current_pool(struct kunit *test)
{
	unsigned long entries[] = { 0x1234567800990000UL };
	depot_stack_handle_t handle;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);
}

static void stackdepot_trie_pool_carve_current(struct kunit *test)
{
	struct stack_depot_trie_pool_mark first;
	struct stack_depot_trie_pool_mark second;
	void *ptr1;
	void *ptr2;
	size_t align = 1UL << DEPOT_STACK_ALIGN;

	stackdepot_trie_pool_seed_current_pool(test);
	ptr1 = __stack_depot_trie_pool_carve_current(1, &first);
	KUNIT_ASSERT_NOT_NULL(test, ptr1);
	KUNIT_EXPECT_TRUE(test, IS_ALIGNED((unsigned long)ptr1, align));
	KUNIT_EXPECT_EQ(test, first.size, align);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&first));

	ptr2 = __stack_depot_trie_pool_carve_current(1, &second);
	KUNIT_ASSERT_NOT_NULL(test, ptr2);
	KUNIT_EXPECT_PTR_EQ(test, ptr2, ptr1);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&second));
	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_pool_try_rollback(&first));
}

static void stackdepot_trie_pool_rollback_requires_lifo(struct kunit *test)
{
	struct stack_depot_trie_pool_mark first;
	struct stack_depot_trie_pool_mark second;
	void *ptr1;
	void *ptr2;

	stackdepot_trie_pool_seed_current_pool(test);
	ptr1 = __stack_depot_trie_pool_carve_current(1, &first);
	KUNIT_ASSERT_NOT_NULL(test, ptr1);
	ptr2 = __stack_depot_trie_pool_carve_current(1, &second);
	KUNIT_ASSERT_NOT_NULL(test, ptr2);

	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_pool_try_rollback(&first));
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&second));
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&first));
}

static void stackdepot_trie_pool_carve_current_rejects_bad_inputs(struct kunit *test)
{
	struct stack_depot_trie_pool_mark mark;
	void *ptr;

	stackdepot_trie_pool_seed_current_pool(test);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_pool_carve_current(0, &mark));
	KUNIT_EXPECT_EQ(test, mark.size, 0UL);
	ptr = __stack_depot_trie_pool_carve_current(DEPOT_POOL_SIZE + 1, &mark);
	KUNIT_EXPECT_NULL(test, ptr);
	KUNIT_EXPECT_EQ(test, mark.size, 0UL);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_pool_carve_current(1, NULL));
	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_pool_try_rollback(NULL));
	memset(&mark, 0, sizeof(mark));
	KUNIT_EXPECT_FALSE(test, __stack_depot_trie_pool_try_rollback(&mark));
}

static void stackdepot_trie_pool_carve_slots(struct kunit *test)
{
	struct stack_depot_trie_child_array_slot child_slots[1] = {
		{ .size = 1 },
	};
	struct stack_depot_trie_node_slot node_slots[2] = {
		{ .size = 1 },
		{ .size = (1UL << DEPOT_STACK_ALIGN) + 1 },
	};
	struct stack_depot_trie_pool_mark mark;
	void *storage = NULL;
	struct stack_depot_trie_pool_request req = {
		.node_slots = node_slots,
		.nr_node_slots = ARRAY_SIZE(node_slots),
		.child_slots = child_slots,
		.nr_child_slots = ARRAY_SIZE(child_slots),
		.storage = &storage,
		.storage_size = 1,
		.mark = &mark,
	};
	size_t child_size;
	size_t node0_size;
	size_t node1_size;
	size_t old_total;
	void *again;
	int ret;

	stackdepot_trie_pool_seed_current_pool(test);
	ret = __stack_depot_trie_pool_carve(&req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[0].node);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[1].node);
	KUNIT_ASSERT_NOT_NULL(test, child_slots[0].array);
	KUNIT_ASSERT_NOT_NULL(test, storage);

	node0_size = __stack_depot_trie_pool_alloc_size(node_slots[0].size);
	node1_size = __stack_depot_trie_pool_alloc_size(node_slots[1].size);
	child_size = __stack_depot_trie_pool_alloc_size(child_slots[0].size);
	old_total = node0_size + node1_size + child_size +
		__stack_depot_trie_pool_alloc_size(1);
	KUNIT_EXPECT_PTR_EQ(test, node_slots[1].node,
			    (char *)node_slots[0].node + node0_size);
	KUNIT_EXPECT_GT(test, (unsigned long)child_slots[0].array,
			(unsigned long)node_slots[1].node + node1_size);
	KUNIT_EXPECT_GT(test, (unsigned long)storage,
			(unsigned long)child_slots[0].array + child_size);
	KUNIT_EXPECT_GT(test, mark.size, old_total);

	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&mark));
	again = __stack_depot_trie_pool_carve_current(1, &mark);
	KUNIT_ASSERT_NOT_NULL(test, again);
	KUNIT_EXPECT_PTR_EQ(test, again, node_slots[0].node);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&mark));
}

static void stackdepot_trie_pool_carve_slots_rejects_bad_inputs(struct kunit *test)
{
	struct stack_depot_trie_child_array_slot child_slot = { .size = 1 };
	struct stack_depot_trie_node_slot node_slot = { .size = 1 };
	struct stack_depot_trie_pool_mark mark;
	void *storage = (void *)0x1UL;
	struct stack_depot_trie_pool_request req = {
		.node_slots = &node_slot,
		.nr_node_slots = 1,
		.child_slots = &child_slot,
		.nr_child_slots = 1,
		.storage = &storage,
		.storage_size = 1,
		.mark = &mark,
	};
	int ret;

	stackdepot_trie_pool_seed_current_pool(test);
	ret = __stack_depot_trie_pool_carve(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, mark.size, 0UL);

	storage = NULL;
	node_slot.node = (void *)0x1UL;
	ret = __stack_depot_trie_pool_carve(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, mark.size, 0UL);

	node_slot.node = NULL;
	req.storage_size = DEPOT_POOL_SIZE;
	ret = __stack_depot_trie_pool_carve(&req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, mark.size, 0UL);
}

static void stackdepot_trie_pool_carve_uses_prealloc(struct kunit *test)
{
	struct stack_depot_trie_pool_mark first_mark;
	struct stack_depot_trie_pool_mark second_mark;
	void *first_storage = NULL;
	void *second_storage = NULL;
	void *prealloc;
	size_t storage_size = DEPOT_POOL_SIZE - 64;
	struct stack_depot_trie_pool_request first = {
		.storage = &first_storage,
		.storage_size = DEPOT_POOL_SIZE - 64,
		.prealloc = &prealloc,
		.mark = &first_mark,
	};
	struct stack_depot_trie_pool_request second = {
		.storage = &second_storage,
		.storage_size = DEPOT_POOL_SIZE - 64,
		.mark = &second_mark,
	};
	int ret;

	stackdepot_trie_pool_seed_current_pool(test);
	KUNIT_ASSERT_GT(test, storage_size, 0UL);
	prealloc = __stack_depot_trie_pool_prealloc(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, prealloc);

	ret = __stack_depot_trie_pool_carve(&first);
	KUNIT_ASSERT_EQ(test, ret, 0);
	__stack_depot_trie_pool_free_prealloc(prealloc);
	KUNIT_ASSERT_NOT_NULL(test, first_storage);
	KUNIT_ASSERT_TRUE(test, first_mark.added_pool);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&first_mark));

	ret = __stack_depot_trie_pool_carve(&second);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, second_storage, first_storage);
	KUNIT_ASSERT_TRUE(test, second_mark.added_pool);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&second_mark));
}

static void stackdepot_trie_pool_carve_no_prealloc_rollover(struct kunit *test)
{
	struct stack_depot_trie_pool_mark marks[2];
	void *storage[ARRAY_SIZE(marks)];
	unsigned int consumed = 0;
	void *failed_storage = NULL;
	struct stack_depot_trie_pool_mark failed_mark;
	struct stack_depot_trie_pool_request failed = {
		.storage = &failed_storage,
		.storage_size = 1,
		.mark = &failed_mark,
	};
	unsigned int i;
	int ret;

	stackdepot_trie_pool_seed_current_pool(test);
	for (i = 0; i < ARRAY_SIZE(marks); i++) {
		size_t storage_size = DEPOT_POOL_SIZE - 64;
		struct stack_depot_trie_pool_request req = {
			.storage = &storage[i],
			.storage_size = DEPOT_POOL_SIZE - 64,
			.mark = &marks[i],
		};

		KUNIT_ASSERT_GT(test, storage_size, 0UL);
		storage[i] = NULL;
		ret = __stack_depot_trie_pool_carve(&req);
		if (ret)
			break;
		KUNIT_ASSERT_NOT_NULL(test, storage[i]);
		consumed++;
	}

	failed.storage_size = DEPOT_POOL_SIZE - 64;
	ret = __stack_depot_trie_pool_carve(&failed);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_NULL(test, failed_storage);
	KUNIT_EXPECT_EQ(test, failed_mark.size, 0UL);

	while (consumed--)
		KUNIT_ASSERT_TRUE(test,
				  __stack_depot_trie_pool_try_rollback(&marks[consumed]));
}

static void stackdepot_trie_alloc_txn_id(struct kunit *test)
{
	struct stack_depot_trie_side_prealloc prealloc = {};
	struct stack_depot_trie_alloc_txn txn;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &prealloc);

	__stack_depot_trie_alloc_txn_init(&txn);
	ret = __stack_depot_trie_alloc_txn_id(&txn, &prealloc);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, prealloc.dir);
	KUNIT_EXPECT_NULL(test, prealloc.chunk);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 1U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	ret = __stack_depot_trie_alloc_txn_id(&txn, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	__stack_depot_trie_alloc_txn_rollback(&txn);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 0UL);
}

static void stackdepot_trie_alloc_txn_reserve(struct kunit *test)
{
	struct stack_depot_trie_node_slot node_slot = { .size = 1 };
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_alloc_request req;
	void *storage = NULL;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &side_prealloc);

	__stack_depot_trie_alloc_txn_init(&txn);
	req = (struct stack_depot_trie_alloc_request) {
		.txn = &txn,
		.node_slots = &node_slot,
		.nr_node_slots = 1,
		.storage = &storage,
		.storage_size = 1,
		.side_prealloc = &side_prealloc,
	};
	ret = __stack_depot_trie_alloc_txn_reserve(&req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, side_prealloc.dir);
	KUNIT_EXPECT_NULL(test, side_prealloc.chunk);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 1U);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	KUNIT_EXPECT_NOT_NULL(test, node_slot.node);
	KUNIT_EXPECT_NOT_NULL(test, storage);

	__stack_depot_trie_alloc_txn_rollback(&txn);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 0UL);
}

static void stackdepot_trie_alloc_txn_reserve_id_failure(struct kunit *test)
{
	struct stack_depot_trie_node_slot node_slot = { .size = 1 };
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_pool_mark mark;
	struct stack_depot_trie_alloc_request req;
	void *storage = NULL;
	void *again;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	__stack_depot_trie_alloc_txn_init(&txn);
	req = (struct stack_depot_trie_alloc_request) {
		.txn = &txn,
		.node_slots = &node_slot,
		.nr_node_slots = 1,
		.storage = &storage,
		.storage_size = 1,
	};
	ret = __stack_depot_trie_alloc_txn_reserve(&req);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_NULL(test, node_slot.node);
	KUNIT_EXPECT_NULL(test, storage);
	again = __stack_depot_trie_pool_carve_current(1, &mark);
	KUNIT_ASSERT_NOT_NULL(test, again);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&mark));
}

static void stackdepot_trie_alloc_txn_commit(struct kunit *test)
{
	struct stack_depot_trie_leaf_update updates[1];
	struct stack_depot_trie_side_prealloc prealloc = {};
	struct stack_depot_trie_alloc_txn txn;
	const void *old_leaf = (const void *)0x1111UL;
	void *pool_leaf;
	u32 old_id;
	u32 leaf_id;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &prealloc);

	__stack_depot_trie_alloc_txn_init(&txn);
	old_id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, old_id, 1U);
	ret = __stack_depot_trie_side_table_store(old_id, old_leaf);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = __stack_depot_trie_alloc_txn_id(&txn, &prealloc);
	KUNIT_ASSERT_EQ(test, ret, 0);
	pool_leaf = __stack_depot_trie_pool_carve_current(1, &txn.pool);
	KUNIT_ASSERT_NOT_NULL(test, pool_leaf);
	updates[0].leaf_id = old_id;
	updates[0].leaf = pool_leaf;
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &txn.side);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(old_id),
			    pool_leaf);
	KUNIT_EXPECT_NE(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_NE(test, txn.side.nr_updates, 0U);
	leaf_id = __stack_depot_trie_alloc_txn_commit(&txn);
	KUNIT_EXPECT_EQ(test, leaf_id, 2U);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.side.nr_updates, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 2UL);

	__stack_depot_trie_alloc_txn_rollback(&txn);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 2UL);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(old_id),
			    pool_leaf);
	pool_leaf = __stack_depot_trie_pool_carve_current(1, &txn.pool);
	KUNIT_ASSERT_NOT_NULL(test, pool_leaf);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&txn.pool));
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_alloc_txn_commit(NULL), 0U);
}

static void stackdepot_trie_alloc_txn_rollback(struct kunit *test)
{
	struct stack_depot_trie_leaf_update updates[2];
	struct stack_depot_trie_alloc_txn txn;
	const void *old_leaf = (const void *)0x1111UL;
	void *pool_leaf;
	u32 old_id;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	__stack_depot_trie_alloc_txn_init(&txn);
	old_id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, old_id, 1U);
	txn.leaf_id = stackdepot_trie_side_table_alloc(test);
	KUNIT_ASSERT_EQ(test, txn.leaf_id, 2U);
	ret = __stack_depot_trie_side_table_store(old_id, old_leaf);
	KUNIT_ASSERT_EQ(test, ret, 0);

	pool_leaf = __stack_depot_trie_pool_carve_current(1, &txn.pool);
	KUNIT_ASSERT_NOT_NULL(test, pool_leaf);
	updates[0].leaf_id = old_id;
	updates[0].leaf = pool_leaf;
	updates[1].leaf_id = txn.leaf_id;
	updates[1].leaf = pool_leaf;
	ret = __stack_depot_trie_side_prepare(updates, ARRAY_SIZE(updates), &txn.side);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(old_id),
			    pool_leaf);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(txn.leaf_id),
			    pool_leaf);

	__stack_depot_trie_alloc_txn_rollback(&txn);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.side.nr_updates, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(old_id),
			    old_leaf);
	KUNIT_EXPECT_NULL(test, __stack_depot_trie_side_table_lookup(2));
	pool_leaf = __stack_depot_trie_pool_carve_current(1, &txn.pool);
	KUNIT_ASSERT_NOT_NULL(test, pool_leaf);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_pool_try_rollback(&txn.pool));
}

static int txn_insert_plan(struct stack_depot_trie_root *root,
			   const unsigned long *entries, unsigned int nr_entries,
			   struct stack_depot_trie_node_slot *node_slots,
			   unsigned int nr_node_slots,
			   struct stack_depot_trie_child_array_slot *child_slots,
			   unsigned int nr_child_slots,
			   struct stack_depot_trie_alloc_txn *txn,
			   void **storage, void **pool_prealloc,
			   struct stack_depot_trie_side_prealloc *side_prealloc,
			   struct stack_depot_trie_alloc_request *req)
{
	return __stack_depot_trie_alloc_txn_plan(root, entries, nr_entries,
					       node_slots, nr_node_slots,
					       child_slots, nr_child_slots, txn,
					       storage, pool_prealloc, side_prealloc,
					       req);
}

static int txn_insert(struct stack_depot_trie_root *root,
		      struct stack_depot_trie_alloc_request *req,
		      const unsigned long *entries, unsigned int nr_entries,
		      const void **tail, u32 *leaf_id)
{
	return __stack_depot_trie_alloc_txn_insert(root, req, entries, nr_entries,
						 NULL, 0, tail, leaf_id);
}

static int workspace_plan(struct stack_depot_trie_root *root,
			  const unsigned long *entries, unsigned int nr_entries,
			  void **pool_prealloc,
			  struct stack_depot_trie_side_prealloc *side_prealloc,
			  struct stack_depot_trie_alloc_workspace *workspace)
{
	return __stack_depot_trie_workspace_plan(root, entries, nr_entries,
					       pool_prealloc, side_prealloc, workspace);
}

static int ws_insert_prealloc(struct stack_depot_trie_root *root,
			      struct stack_depot_trie_alloc_workspace *workspace,
			      const unsigned long *entries, unsigned int nr_entries,
			      struct stack_depot_trie_side_prealloc *side_prealloc,
			      const void **tail, u32 *leaf_id)
{
	return __stack_depot_trie_workspace_insert(root, entries, nr_entries, NULL,
						 side_prealloc, workspace, tail, leaf_id);
}

static depot_stack_handle_t save_miss(struct stack_depot_trie_root *root,
				      const unsigned long *entries,
				      unsigned int nr_entries, gfp_t gfp_flags,
				      depot_flags_t depot_flags,
				      struct stack_depot_trie_alloc_workspace *workspace)
{
	return __stack_depot_trie_save_miss(root, entries, nr_entries, gfp_flags,
					  depot_flags, workspace);
}

static depot_stack_handle_t tsave(struct stack_depot_trie_root *root,
				  const unsigned long *entries, unsigned int nr_entries,
				  gfp_t gfp_flags, depot_flags_t depot_flags,
				  struct stack_depot_trie_alloc_workspace *workspace)
{
	return __stack_depot_trie_save(root, entries, nr_entries, gfp_flags,
				    depot_flags, workspace);
}

static depot_stack_handle_t
tsave_locked(struct stack_depot_trie_root *root, const unsigned long *entries,
	     unsigned int nr_entries, gfp_t gfp_flags, depot_flags_t depot_flags,
	     struct stack_depot_trie_alloc_workspace *workspace,
	     raw_spinlock_t *workspace_lock)
{
	return __stack_depot_trie_save_locked(root, entries, nr_entries, gfp_flags,
					   depot_flags, workspace, workspace_lock);
}

static unsigned int tfetch_handle(depot_stack_handle_t handle,
				  unsigned long *entries, unsigned int max_entries)
{
	return __stack_depot_trie_fetch_handle_into(handle, entries, max_entries);
}

struct trie_frame_iter_ctx {
	unsigned long entries[CONFIG_STACKDEPOT_MAX_FRAMES];
	unsigned int nr_entries;
};

static void trie_frame_iter_record(unsigned int index, unsigned long frame,
				   void *data)
{
	struct trie_frame_iter_ctx *ctx = data;

	ctx->entries[index] = frame;
	ctx->nr_entries++;
}

static unsigned int twalk_frames(const void *leaf, struct trie_frame_iter_ctx *ctx)
{
	return __stack_depot_trie_walk_frames(leaf, trie_frame_iter_record, ctx);
}

static void stackdepot_trie_alloc_workspace_plan(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_side_prealloc side_prealloc = {
		.chunk = (void *)0x2222UL,
	};
	struct stack_depot_trie_root root = {};
	void *pool_prealloc = (void *)0x1111UL;
	const void *tail = NULL;
	u32 leaf_id = 0;
	int ret;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);

	ret = workspace_plan(&root, entries, ARRAY_SIZE(entries), &pool_prealloc,
			     &side_prealloc, workspace);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.txn, &workspace->txn);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.node_slots,
			    &workspace->node_slots[0]);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.child_slots,
			    &workspace->child_slots[0]);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.storage, &workspace->storage);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.pool_prealloc, &pool_prealloc);
	KUNIT_EXPECT_PTR_EQ(test, workspace->req.side_prealloc, &side_prealloc);
	KUNIT_EXPECT_NE(test, workspace->req.storage_size, 0UL);
	KUNIT_EXPECT_EQ(test, workspace->req.nr_node_slots, 1U);
	KUNIT_EXPECT_EQ(test, workspace->req.nr_child_slots, 0U);

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	side_prealloc = (struct stack_depot_trie_side_prealloc) {};
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &side_prealloc);
	ret = workspace_plan(&root, entries, ARRAY_SIZE(entries), NULL,
			     &side_prealloc, workspace);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = ws_insert_prealloc(&root, workspace, entries, ARRAY_SIZE(entries),
				 &side_prealloc, &tail, &leaf_id);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, leaf_id, 1U);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, entries, ARRAY_SIZE(entries)),
			    tail);
}

static void stackdepot_trie_alloc_workspace_insert(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	const void *tail = NULL;
	unsigned int fetched;
	u32 leaf_id = 0;
	int ret;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &side_prealloc);

	ret = ws_insert_prealloc(&root, workspace, entries, ARRAY_SIZE(entries),
				 &side_prealloc, &tail, &leaf_id);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, leaf_id, 1U);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(leaf_id),
			    tail);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, entries, ARRAY_SIZE(entries)),
			    tail);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	ret = ws_insert_prealloc(NULL, workspace, entries, ARRAY_SIZE(entries),
				 &side_prealloc, &tail, &leaf_id);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_save_miss(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	depot_stack_handle_t handle;
	const void *tail;
	unsigned int fetched;
	u32 leaf_id;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	handle = save_miss(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
			   STACK_DEPOT_FLAG_CAN_ALLOC, workspace);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);
	leaf_id = __stack_depot_trie_leaf_id(handle);
	KUNIT_EXPECT_EQ(test, leaf_id, 1U);
	tail = __stack_depot_trie_side_table_lookup(leaf_id);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, entries, ARRAY_SIZE(entries)),
			    tail);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	handle = save_miss(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
			   STACK_DEPOT_FLAG_GET, workspace);
	KUNIT_EXPECT_EQ(test, handle, (depot_stack_handle_t)0);
	handle = save_miss(NULL, entries, ARRAY_SIZE(entries), GFP_KERNEL, 0,
			   workspace);
	KUNIT_EXPECT_EQ(test, handle, (depot_stack_handle_t)0);
}

static void stackdepot_trie_save_miss_noalloc(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_root root = {};
	depot_stack_handle_t handle;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	handle = save_miss(&root, entries, ARRAY_SIZE(entries), GFP_NOWAIT, 0,
			   workspace);
	KUNIT_EXPECT_EQ(test, handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_NULL(test, find_leaf(&root, entries, ARRAY_SIZE(entries)));
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 0UL);
}

static void stackdepot_trie_save(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_root root = {};
	depot_stack_handle_t first;
	depot_stack_handle_t invalid;
	depot_stack_handle_t second;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	first = tsave(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
		      STACK_DEPOT_FLAG_CAN_ALLOC, workspace);
	KUNIT_ASSERT_NE(test, first, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);

	second = tsave(&root, entries, ARRAY_SIZE(entries), GFP_NOWAIT, 0,
		       workspace);
	KUNIT_EXPECT_EQ(test, second, first);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);

	invalid = tsave(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
			STACK_DEPOT_FLAG_GET, workspace);
	KUNIT_EXPECT_EQ(test, invalid, (depot_stack_handle_t)0);
	invalid = tsave(NULL, entries, ARRAY_SIZE(entries), GFP_KERNEL, 0, workspace);
	KUNIT_EXPECT_EQ(test, invalid, (depot_stack_handle_t)0);
}

static void stackdepot_trie_save_locked(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct stack_depot_trie_root root = {};
	raw_spinlock_t workspace_lock;
	depot_stack_handle_t first;
	depot_stack_handle_t get;
	depot_stack_handle_t second;
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned int fetched;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	raw_spin_lock_init(&workspace_lock);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	first = tsave_locked(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
			     STACK_DEPOT_FLAG_CAN_ALLOC, workspace, &workspace_lock);
	KUNIT_ASSERT_NE(test, first, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	fetched = tfetch_handle(first, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	second = tsave_locked(&root, entries, ARRAY_SIZE(entries), GFP_NOWAIT, 0,
			      workspace, &workspace_lock);
	KUNIT_EXPECT_EQ(test, second, first);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);

	get = tsave_locked(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
			   STACK_DEPOT_FLAG_GET, workspace, &workspace_lock);
	KUNIT_EXPECT_EQ(test, get, (depot_stack_handle_t)0);
	get = tsave_locked(NULL, entries, ARRAY_SIZE(entries), GFP_KERNEL, 0,
			   workspace, &workspace_lock);
	KUNIT_EXPECT_EQ(test, get, (depot_stack_handle_t)0);
}

static void stackdepot_trie_fetch_handle_into(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	struct trie_frame_iter_ctx *iter;
	struct stack_depot_trie_root root = {};
	unsigned long small[1] = { 0xdeadUL };
	unsigned long out[ARRAY_SIZE(entries)] = {};
	depot_stack_handle_t hash_handle;
	depot_stack_handle_t handle;
	const void *leaf;
	unsigned int invalid;
	unsigned int fetched;
	u32 leaf_id;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	iter = kunit_kzalloc(test, sizeof(*iter), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, iter);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	handle = tsave(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
		       STACK_DEPOT_FLAG_CAN_ALLOC, workspace);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);
	leaf_id = __stack_depot_trie_leaf_id(handle);
	KUNIT_ASSERT_NE(test, leaf_id, 0U);
	leaf = __stack_depot_trie_side_table_lookup(leaf_id);
	KUNIT_ASSERT_NOT_NULL(test, leaf);
	fetched = twalk_frames(leaf, iter);
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, iter->nr_entries, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, iter->entries, entries, sizeof(entries));
	iter->nr_entries = 0;
	fetched = twalk_frames(NULL, iter);
	KUNIT_EXPECT_EQ(test, fetched, 0U);
	KUNIT_EXPECT_EQ(test, iter->nr_entries, 0U);
	fetched = tfetch_handle(handle, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	fetched = tfetch_handle(handle, small, ARRAY_SIZE(small));
	KUNIT_EXPECT_EQ(test, fetched, 0U);
	KUNIT_EXPECT_EQ(test, small[0], 0xdeadUL);
	fetched = stack_depot_fetch_into(handle, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
	fetched = stack_depot_fetch_into(handle, small, ARRAY_SIZE(small));
	KUNIT_EXPECT_EQ(test, fetched, 0U);
	KUNIT_EXPECT_EQ(test, small[0], 0xdeadUL);
	invalid = tfetch_handle(0, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, invalid, 0U);
	invalid = tfetch_handle(handle, NULL, 0);
	KUNIT_EXPECT_EQ(test, invalid, 0U);
	fetched = tfetch_handle(handle, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	hash_handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, hash_handle, (depot_stack_handle_t)0);
	invalid = tfetch_handle(hash_handle, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, invalid, 0U);
}

static void stackdepot_trie_snprint_public(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	struct stack_depot_trie_alloc_workspace *workspace;
	char expected[256];
	char actual[256];
	struct stack_depot_trie_root root = {};
	depot_stack_handle_t extra;
	depot_stack_handle_t handle;
	unsigned int expected_len;
	int actual_len;

	workspace = kunit_kzalloc(test, sizeof(*workspace), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, workspace);
	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);

	handle = tsave(&root, entries, ARRAY_SIZE(entries), GFP_KERNEL,
		       STACK_DEPOT_FLAG_CAN_ALLOC, workspace);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);

	expected_len = stack_trace_snprint(expected, sizeof(expected), entries,
					   ARRAY_SIZE(entries), 2);
	extra = stack_depot_set_extra_bits(handle, 7);
	actual_len = stack_depot_snprint(extra, actual, sizeof(actual), 2);
	KUNIT_EXPECT_EQ(test, actual_len, (int)expected_len);
	KUNIT_EXPECT_STREQ(test, actual, expected);
}

static void stackdepot_trie_alloc_txn_plan(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_alloc_request req;
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_root root = {};
	struct stack_depot_trie_side_prealloc side_prealloc = {
		.chunk = (void *)0x2222UL,
	};
	void *pool_prealloc = (void *)0x1111UL;
	void *storage = (void *)0x3333UL;
	int ret;

	ret = txn_insert_plan(&root, entries, ARRAY_SIZE(entries), &node_slot, 1,
			      &child_slot, 1, &txn, &storage, &pool_prealloc,
			      &side_prealloc, &req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, req.txn, &txn);
	KUNIT_EXPECT_PTR_EQ(test, req.node_slots, &node_slot);
	KUNIT_EXPECT_EQ(test, req.nr_node_slots, 1U);
	KUNIT_EXPECT_PTR_EQ(test, req.child_slots, &child_slot);
	KUNIT_EXPECT_EQ(test, req.nr_child_slots, 0U);
	KUNIT_EXPECT_PTR_EQ(test, req.storage, &storage);
	KUNIT_EXPECT_PTR_EQ(test, req.pool_prealloc, &pool_prealloc);
	KUNIT_EXPECT_PTR_EQ(test, req.side_prealloc, &side_prealloc);
	KUNIT_EXPECT_NE(test, req.storage_size, 0UL);
	KUNIT_EXPECT_NULL(test, storage);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_EQ(test, txn.side.nr_updates, 0U);

	ret = txn_insert_plan(NULL, entries, ARRAY_SIZE(entries), &node_slot, 1,
			      &child_slot, 1, &txn, &storage, &pool_prealloc,
			      &side_prealloc, &req);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_alloc_txn_insert(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot child_slots[1];
	struct stack_depot_trie_node_slot node_slots[1];
	struct stack_depot_trie_alloc_request req;
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_root root = {};
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	const void *tail = NULL;
	void *storage = NULL;
	unsigned int fetched;
	u32 leaf_id = 0;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &side_prealloc);

	ret = txn_insert_plan(&root, entries, ARRAY_SIZE(entries), node_slots,
			      ARRAY_SIZE(node_slots), child_slots,
			      ARRAY_SIZE(child_slots), &txn, &storage,
			      NULL, &side_prealloc, &req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = txn_insert(&root, &req, entries, ARRAY_SIZE(entries), &tail, &leaf_id);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, leaf_id, 1U);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.side.nr_updates, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(leaf_id),
			    tail);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, entries, ARRAY_SIZE(entries)),
			    tail);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));

	__stack_depot_trie_alloc_txn_rollback(&txn);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 1UL);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(leaf_id),
			    tail);
}

static void stackdepot_trie_alloc_txn_insert_stale_plan(struct kunit *test)
{
	unsigned long first[] = { 0x1000UL };
	unsigned long second[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_slots[1];
	struct stack_depot_trie_child_array_slot fresh_child_slots[1];
	struct stack_depot_trie_node_slot node_slots[1];
	struct stack_depot_trie_node_slot fresh_node_slots[1];
	struct stack_depot_trie_alloc_request req;
	struct stack_depot_trie_alloc_request fresh_req;
	struct stack_depot_trie_alloc_txn txn;
	struct stack_depot_trie_alloc_txn fresh_txn;
	struct stack_depot_trie_root root = {};
	struct stack_depot_trie_side_prealloc side_prealloc = {};
	const void *tail = NULL;
	const void *fresh_tail = NULL;
	void *storage = NULL;
	void *fresh_storage = NULL;
	u32 leaf_id = 0;
	u32 fresh_leaf_id = 0;
	int ret;

	stackdepot_trie_side_table_init_or_skip(test);
	stackdepot_trie_pool_seed_current_pool(test);
	if (__stack_depot_trie_side_table_prealloc_needed())
		stackdepot_trie_side_table_prealloc_or_fail(test, &side_prealloc);

	ret = txn_insert_plan(&root, first, ARRAY_SIZE(first), fresh_node_slots,
			      ARRAY_SIZE(fresh_node_slots), fresh_child_slots,
			      ARRAY_SIZE(fresh_child_slots), &fresh_txn,
			      &fresh_storage, NULL, &side_prealloc, &fresh_req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = txn_insert(&root, &fresh_req, first, ARRAY_SIZE(first), &fresh_tail,
			 &fresh_leaf_id);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, fresh_leaf_id, 1U);

	ret = txn_insert_plan(&root, second, ARRAY_SIZE(second), node_slots,
			      ARRAY_SIZE(node_slots), child_slots,
			      ARRAY_SIZE(child_slots), &txn, &storage,
			      NULL, &side_prealloc, &req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = txn_insert_plan(&root, second, ARRAY_SIZE(second), fresh_node_slots,
			      ARRAY_SIZE(fresh_node_slots), fresh_child_slots,
			      ARRAY_SIZE(fresh_child_slots), &fresh_txn,
			      &fresh_storage, NULL, &side_prealloc, &fresh_req);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = txn_insert(&root, &fresh_req, second, ARRAY_SIZE(second), &fresh_tail,
			 &fresh_leaf_id);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, fresh_leaf_id, 2U);

	ret = txn_insert(&root, &req, second, ARRAY_SIZE(second), &tail, &leaf_id);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, leaf_id, 0U);
	KUNIT_EXPECT_NULL(test, tail);
	KUNIT_EXPECT_EQ(test, txn.leaf_id, 0U);
	KUNIT_EXPECT_EQ(test, txn.side.nr_updates, 0U);
	KUNIT_EXPECT_EQ(test, txn.pool.size, 0UL);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_side_table_entries(), 2UL);
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(1),
			    find_leaf(&root, first, ARRAY_SIZE(first)));
	KUNIT_EXPECT_PTR_EQ(test, __stack_depot_trie_side_table_lookup(2),
			    find_leaf(&root, second, ARRAY_SIZE(second)));
	KUNIT_EXPECT_NULL(test, storage);
	KUNIT_EXPECT_NULL(test, node_slots[0].node);
}

static void stackdepot_frame_raw_fallback(struct kunit *test)
{
	unsigned long frame = 0xffff888000001000UL;
	unsigned long out = 0x12345678UL;
	u32 low = 0xfeedbeef;
	u8 prefix_id = 0xaa;

#ifdef CONFIG_ARM64
	frame = arch_stack_depot_frame_text_prefix();
	if (frame <= ~0UL - 2 * SZ_4G)
		frame += 2 * SZ_4G;
	else
		frame -= 2 * SZ_4G;
	frame |= 0x1000UL;
#endif

	/* Arch hooks may exist, but this frame is chosen to stay raw. */
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_frame_try_compress(frame, &prefix_id, &low));
	KUNIT_EXPECT_EQ(test, prefix_id, (u8)0xaa);
	KUNIT_EXPECT_EQ(test, low, (u32)0xfeedbeef);

	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_frame_decompress(0xff, 0x81234567, &out));
	KUNIT_EXPECT_EQ(test, out, 0x12345678UL);

	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_frame_decompress(0, 0x81234567, NULL));
}

#ifdef CONFIG_X86_64
static void stackdepot_frame_x86_64(struct kunit *test)
{
	unsigned long direct_map = 0xffff888000001000UL;
	unsigned long frame = 0xffffffff81234567UL;
	unsigned long out;
	bool compressed;
	u32 low;
	u8 prefix_id;

	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_frame_try_compress(frame, &prefix_id, &low));
	KUNIT_EXPECT_EQ(test, prefix_id, (u8)0);
	KUNIT_EXPECT_EQ(test, low, (u32)0x81234567);
	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_frame_decompress(prefix_id, low, &out));
	KUNIT_EXPECT_EQ(test, out, frame);

	compressed = __stack_depot_frame_try_compress(direct_map, &prefix_id, &low);
	KUNIT_EXPECT_FALSE(test, compressed);
	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_frame_decompress(1, low, &out));
}
#endif /* CONFIG_X86_64 */

#ifdef CONFIG_ARM64
static void stackdepot_frame_arm64(struct kunit *test)
{
	unsigned long frame = (unsigned long)stackdepot_frame_arm64;
	unsigned long text_prefix = arch_stack_depot_frame_text_prefix();
	unsigned long out;
	bool decoded;
	u32 low;
	u8 prefix_id;

	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_frame_try_compress(frame, &prefix_id, &low));
	KUNIT_EXPECT_EQ(test, low, (u32)frame);
	KUNIT_EXPECT_TRUE(test,
			  __stack_depot_frame_decompress(prefix_id, low, &out));
	KUNIT_EXPECT_EQ(test, out, frame);

	if (text_prefix > SZ_4G) {
		frame = (text_prefix - SZ_4G) | 0x12345678UL;
		KUNIT_EXPECT_TRUE(test,
				  __stack_depot_frame_try_compress(frame, &prefix_id, &low));
		KUNIT_EXPECT_EQ(test, prefix_id, (u8)STACK_DEPOT_ARM64_PREV_PREFIX_ID);
		KUNIT_EXPECT_TRUE(test,
				  __stack_depot_frame_decompress(prefix_id, low, &out));
		KUNIT_EXPECT_EQ(test, out, frame);
	} else {
		prefix_id = STACK_DEPOT_ARM64_PREV_PREFIX_ID;
		decoded = __stack_depot_frame_decompress(prefix_id, 0, &out);
		KUNIT_EXPECT_FALSE(test, decoded);
	}

	if (text_prefix <= ~0UL - SZ_4G) {
		frame = (text_prefix + SZ_4G) | 0x87654321UL;
		KUNIT_EXPECT_TRUE(test,
				  __stack_depot_frame_try_compress(frame, &prefix_id, &low));
		KUNIT_EXPECT_EQ(test, prefix_id, (u8)STACK_DEPOT_ARM64_NEXT_PREFIX_ID);
		KUNIT_EXPECT_TRUE(test,
				  __stack_depot_frame_decompress(prefix_id, low, &out));
		KUNIT_EXPECT_EQ(test, out, frame);
	} else {
		prefix_id = STACK_DEPOT_ARM64_NEXT_PREFIX_ID;
		decoded = __stack_depot_frame_decompress(prefix_id, 0, &out);
		KUNIT_EXPECT_FALSE(test, decoded);
	}

	KUNIT_EXPECT_FALSE(test,
			   __stack_depot_frame_decompress(3, low, &out));
}
#endif /* CONFIG_ARM64 */

static void stackdepot_frame_run_raw_roundtrip(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long out[ARRAY_SIZE(entries)] = {};
	struct stack_depot_frame_run run;
	unsigned char payload[sizeof(entries)];
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, run.mode, STACK_DEPOT_FRAME_RAW);
	KUNIT_EXPECT_EQ(test, run.nr_entries,
			(unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, run.bytes, sizeof(entries));

	ret = frame_run_write(&run, entries, payload, sizeof(payload), NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = frame_run_read(&run, payload, run.bytes, out, ARRAY_SIZE(out), NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

#ifdef CONFIG_ARM64
static void stackdepot_frame_run_arm64_roundtrip(struct kunit *test)
{
	unsigned long entries[] = {
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
	};
	unsigned long read_scratch[ARRAY_SIZE(entries)];
	unsigned long out[ARRAY_SIZE(entries)] = {};
	struct stack_depot_frame_run run;
	u32 payload[ARRAY_SIZE(entries)];
	u32 write_scratch[ARRAY_SIZE(entries)];
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, run.mode, STACK_DEPOT_FRAME_COMPRESSED);
	KUNIT_EXPECT_EQ(test, run.nr_entries,
			(unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, run.bytes, sizeof(payload));

	ret = frame_run_write(&run, entries, payload, sizeof(payload),
			      write_scratch, ARRAY_SIZE(write_scratch));
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = frame_run_read(&run, payload, run.bytes, out, ARRAY_SIZE(out),
			     read_scratch, ARRAY_SIZE(read_scratch));
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}
#endif

#ifdef CONFIG_X86_64
static void stackdepot_frame_run_x86_64_roundtrip(struct kunit *test)
{
	unsigned long entries[] = {
		0xffffffff81000001UL,
		0xffffffff81000002UL,
		0xffffffff81000003UL,
	};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned long read_scratch[ARRAY_SIZE(entries)];
	struct stack_depot_frame_run run;
	u32 payload[ARRAY_SIZE(entries)];
	u32 write_scratch[ARRAY_SIZE(entries)];
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, run.mode, STACK_DEPOT_FRAME_COMPRESSED);
	KUNIT_EXPECT_EQ(test, run.prefix_id, (u8)0);
	KUNIT_EXPECT_EQ(test, run.nr_entries,
			(unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, run.bytes, sizeof(payload));

	ret = frame_run_write(&run, entries, payload, sizeof(payload),
			      write_scratch, ARRAY_SIZE(write_scratch));
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = frame_run_read(&run, payload, run.bytes, out, ARRAY_SIZE(out),
			     read_scratch, ARRAY_SIZE(read_scratch));
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_frame_run_x86_64_boundary(struct kunit *test)
{
	unsigned long entries[] = {
		0xffffffff81000001UL,
		0xffffffff81000002UL,
		0xffff888000000003UL,
		0xffffffff81000004UL,
	};
	struct stack_depot_frame_run run;
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, run.mode, STACK_DEPOT_FRAME_COMPRESSED);
	KUNIT_EXPECT_EQ(test, run.nr_entries, 2U);

	ret = frame_run_init(&entries[2], 2, &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, run.mode, STACK_DEPOT_FRAME_RAW);
	KUNIT_EXPECT_EQ(test, run.nr_entries, 1U);
}

static void stackdepot_frame_run_x86_64_write_rejects_mismatch(struct kunit *test)
{
	unsigned long good[] = {
		0xffffffff81000001UL,
		0xffffffff81000002UL,
	};
	unsigned long bad[] = {
		0xffffffff81000001UL,
		0xffff888000000002UL,
	};
	u32 payload[ARRAY_SIZE(good)] = { 0xa5a5a5a5, 0xb6b6b6b6 };
	u32 scratch[ARRAY_SIZE(good)];
	u32 old[ARRAY_SIZE(payload)];
	struct stack_depot_frame_run run;
	int ret;

	memcpy(old, payload, sizeof(old));
	ret = frame_run_init(good, ARRAY_SIZE(good), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);
	ret = frame_run_write(&run, bad, payload, sizeof(payload), scratch,
			      ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, payload, old, sizeof(payload));
}
#endif /* CONFIG_X86_64 */

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_frame_run_compressed_rejects_src_scratch_overlap(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
#endif
	};
	unsigned long alias[ARRAY_SIZE(entries)] = {};
	unsigned long out[ARRAY_SIZE(entries)] = { 0xa5a5UL, 0xb6b6UL };
	unsigned long old[ARRAY_SIZE(out)];
	struct stack_depot_frame_run run;
	u32 payload[ARRAY_SIZE(entries)];
	u32 write_scratch[ARRAY_SIZE(entries)];
	int ret;

	memcpy(old, out, sizeof(old));
	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, run.mode, STACK_DEPOT_FRAME_COMPRESSED);
	ret = frame_run_write(&run, entries, payload, sizeof(payload),
			      write_scratch, ARRAY_SIZE(write_scratch));
	KUNIT_ASSERT_EQ(test, ret, 0);
	memcpy(alias, payload, run.bytes);

	ret = frame_run_read(&run, alias, run.bytes, out, ARRAY_SIZE(out),
			     alias, ARRAY_SIZE(alias));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, out, old, sizeof(out));
}
#endif

static void stackdepot_frame_run_invalid_inputs(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	unsigned long out[ARRAY_SIZE(entries)] = { 0xa5a5a5a5UL };
	unsigned long old[ARRAY_SIZE(out)];
	struct stack_depot_frame_run run;
	unsigned char payload[sizeof(entries)];
	int ret;

	memcpy(old, out, sizeof(old));
	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = frame_run_init(NULL, ARRAY_SIZE(entries), &run);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_init(entries, 0, &run);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_init(entries, ARRAY_SIZE(entries), NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_write(&run, entries, NULL, run.bytes, NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_write(&run, entries, payload, run.bytes - 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_read(&run, payload, run.bytes - 1, out, ARRAY_SIZE(out),
			     NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = frame_run_read(&run, payload, run.bytes, out, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, out, old, sizeof(out));
}

static void stackdepot_trie_node_raw_roundtrip(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned int fetched;
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 7, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_trie_node_parent_chain(struct kunit *test)
{
	unsigned long root_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long child_entries[] = { 0x3000UL, 0x4000UL };
	unsigned long expected[] = { 0x1000UL, 0x2000UL, 0x3000UL, 0x4000UL };
	unsigned long out[ARRAY_SIZE(expected)] = {};
	unsigned int fetched;
	void *root;
	void *child;

	trie_node_alloc(test, root_entries, ARRAY_SIZE(root_entries), NULL, 0,
			&root);
	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), root, 9,
			&child);
	fetched = tfetch(child, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

static void stackdepot_trie_node_slice_raw(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long expected[] = { 0x2000UL, 0x3000UL };
	struct stack_depot_frame_run run;
	unsigned long out[ARRAY_SIZE(expected)] = {};
	unsigned int fetched;
	void *source;
	void *slice;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &source);
	ret = frame_run_init(&entries[1], ARRAY_SIZE(expected), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	slice = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slice);
	ret = tnode_init_slice(slice, size, NULL, 10, source, 1,
			       ARRAY_SIZE(expected));
	KUNIT_ASSERT_EQ(test, ret, 0);
	fetched = tfetch(slice, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
	KUNIT_EXPECT_EQ(test, tmatch(slice, expected, ARRAY_SIZE(expected)),
			(unsigned int)ARRAY_SIZE(expected));
}

static void stackdepot_trie_node_slice_parent_chain(struct kunit *test)
{
	unsigned long root_entries[] = { 0x1000UL };
	unsigned long entries[] = { 0x2000UL, 0x3000UL, 0x4000UL };
	unsigned long expected[] = { 0x1000UL, 0x3000UL, 0x4000UL };
	struct stack_depot_frame_run run;
	unsigned long out[ARRAY_SIZE(expected)] = {};
	unsigned int fetched;
	void *root;
	void *source;
	void *slice;
	size_t size;
	int ret;

	trie_node_alloc(test, root_entries, ARRAY_SIZE(root_entries), NULL, 0,
			&root);
	trie_node_alloc(test, entries, ARRAY_SIZE(entries), root, 0, &source);
	ret = frame_run_init(&entries[1], 2, &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	slice = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slice);
	ret = tnode_init_slice(slice, size, root, 11, source, 1, 2);
	KUNIT_ASSERT_EQ(test, ret, 0);
	fetched = tfetch(slice, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_node_slice_compressed(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
		arch_stack_depot_frame_text_prefix() | 0x3000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
		0xffffffff81003000UL,
#endif
	};
	unsigned long expected[] = { entries[1], entries[2] };
	struct stack_depot_frame_run run;
	unsigned long out[ARRAY_SIZE(expected)] = {};
	unsigned int fetched;
	void *source;
	void *slice;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &source);
	ret = frame_run_init(&entries[1], ARRAY_SIZE(expected), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test, run.mode, STACK_DEPOT_FRAME_COMPRESSED);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	slice = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slice);
	ret = tnode_init_slice(slice, size, NULL, 12, source, 1,
			       ARRAY_SIZE(expected));
	KUNIT_ASSERT_EQ(test, ret, 0);
	fetched = tfetch(slice, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}
#endif

static void stackdepot_trie_node_slice_rejects_bad_inputs(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_frame_run run;
	void *source;
	void *slice;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &source);
	ret = frame_run_init(entries, 1, &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	slice = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, slice);

	KUNIT_EXPECT_EQ(test, tnode_init_slice(NULL, size, NULL, 1, source, 0, 1),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, tnode_init_slice(slice, size, NULL, 1, NULL, 0, 1),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, tnode_init_slice(slice, size, NULL, 1, source, 0, 0),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, tnode_init_slice(slice, size, NULL, 1, source, 2, 1),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, tnode_init_slice(slice, size - 1, NULL, 1, source, 0, 1),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, tnode_init_slice(source, size, NULL, 1, source, 0, 1),
			-EINVAL);
}

static void stackdepot_trie_node_rejects_stack_len_overflow(struct kunit *test)
{
	unsigned long exact_child[] = { 0x80000000UL };
	unsigned long overflow_child[] = { 0x80001000UL, 0x80002000UL };
	unsigned int parent_len = CONFIG_STACKDEPOT_MAX_FRAMES - 1;
	struct stack_depot_frame_run run;
	unsigned long *parent_entries;
	void *parent;
	void *child;
	size_t size;
	int ret;

	if (CONFIG_STACKDEPOT_MAX_FRAMES < 2) {
		kunit_skip(test, "stack length overflow test needs at least two frames");
		return;
	}

	parent_entries = kunit_kcalloc(test, parent_len, sizeof(*parent_entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, parent_entries);
	trie_fill_raw_entries(parent_entries, parent_len, 0x1000UL);
	KUNIT_ASSERT_EQ(test, frame_run_init(parent_entries, parent_len, &run), 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	parent = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	ret = tnode_init(parent, size, NULL, 0, parent_entries, parent_len,
			 NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = frame_run_init(exact_child, ARRAY_SIZE(exact_child), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	size = __stack_depot_trie_node_size(&run);
	child = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child);
	ret = tnode_init(child, size, parent, 1, exact_child,
			 ARRAY_SIZE(exact_child), NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = frame_run_init(overflow_child, ARRAY_SIZE(overflow_child), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	size = __stack_depot_trie_node_size(&run);
	child = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child);
	ret = tnode_init(child, size, parent, 2, overflow_child,
			 ARRAY_SIZE(overflow_child), NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_node_match_raw(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long mismatch[] = { 0x1000UL, 0x2222UL, 0x3000UL };
	unsigned long short_input[] = { 0x1000UL, 0x2000UL };
	unsigned long long_input[] = {
		0x1000UL, 0x2000UL, 0x3000UL, 0x4000UL,
	};
	unsigned long first_mismatch[] = { 0x9000UL, 0x2000UL };
	unsigned int matched;
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 7, &node);
	KUNIT_EXPECT_EQ(test, tmatch(node, entries, ARRAY_SIZE(entries)),
			(unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, tmatch(node, mismatch, ARRAY_SIZE(mismatch)), 1U);
	KUNIT_EXPECT_EQ(test, tmatch(node, short_input, ARRAY_SIZE(short_input)),
			(unsigned int)ARRAY_SIZE(short_input));
	KUNIT_EXPECT_EQ(test, tmatch(node, long_input, ARRAY_SIZE(long_input)),
			(unsigned int)ARRAY_SIZE(entries));
	matched = tmatch(node, first_mismatch, ARRAY_SIZE(first_mismatch));
	KUNIT_EXPECT_EQ(test, matched, 0U);
	KUNIT_EXPECT_EQ(test, tmatch(NULL, entries, ARRAY_SIZE(entries)), 0U);
	KUNIT_EXPECT_EQ(test, tmatch(node, NULL, ARRAY_SIZE(entries)), 0U);
	KUNIT_EXPECT_EQ(test, tmatch(node, entries, 0), 0U);
}

static void stackdepot_trie_append_chain_raw(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	struct stack_depot_frame_run run;
	struct stack_depot_trie_node_slot node_slots[1];
	unsigned long out[ARRAY_SIZE(entries)] = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	unsigned int fetched;
	size_t size;
	int ret;

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, ARRAY_SIZE(entries), &run), 0);
	size = __stack_depot_trie_node_size(&run);
	node_slots[0].node = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[0].node);
	node_slots[0].size = size;

	ret = append_chain(NULL, 13, entries, ARRAY_SIZE(entries), node_slots,
			   ARRAY_SIZE(node_slots), NULL, 0, NULL, 0, &head, &tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, head, node_slots[0].node);
	KUNIT_EXPECT_PTR_EQ(test, tail, node_slots[0].node);
	KUNIT_EXPECT_EQ(test, used, 1U);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_trie_append_chain_parent(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long entries[] = { 0x2000UL, 0x3000UL };
	unsigned long expected[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	struct stack_depot_frame_run run;
	struct stack_depot_trie_node_slot node_slots[1];
	unsigned long out[ARRAY_SIZE(expected)] = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	unsigned int fetched;
	void *parent;
	size_t size;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	KUNIT_ASSERT_EQ(test, frame_run_init(entries, ARRAY_SIZE(entries), &run), 0);
	size = __stack_depot_trie_node_size(&run);
	node_slots[0].node = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[0].node);
	node_slots[0].size = size;

	ret = append_chain(parent, 14, entries, ARRAY_SIZE(entries), node_slots,
			   ARRAY_SIZE(node_slots), NULL, 0, NULL, 0, &head, &tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, head, tail);
	KUNIT_EXPECT_EQ(test, used, 1U);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

static void stackdepot_trie_append_chain_rejects_stack_len_overflow(struct kunit *test)
{
	unsigned long entries[] = { 0x80001000UL, 0x80002000UL };
	unsigned int parent_len = CONFIG_STACKDEPOT_MAX_FRAMES - 1;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_frame_run run;
	unsigned long *parent_entries;
	unsigned char *old;
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 99;
	void *parent;
	size_t size;
	int ret;

	if (CONFIG_STACKDEPOT_MAX_FRAMES < 2) {
		kunit_skip(test, "stack length overflow test needs at least two frames");
		return;
	}

	parent_entries = kunit_kcalloc(test, parent_len, sizeof(*parent_entries), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, parent_entries);
	trie_fill_raw_entries(parent_entries, parent_len, 0x1000UL);
	KUNIT_ASSERT_EQ(test, frame_run_init(parent_entries, parent_len, &run), 0);
	size = __stack_depot_trie_node_size(&run);
	parent = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, parent);
	ret = tnode_init(parent, size, NULL, 0, parent_entries, parent_len,
			 NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, ARRAY_SIZE(entries), &run), 0);
	node_slot.size = __stack_depot_trie_node_size(&run);
	node_slot.node = kunit_kzalloc(test, node_slot.size, GFP_KERNEL);
	old = kunit_kzalloc(test, node_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, node_slot.node);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(node_slot.node, 0xaa, node_slot.size);
	memcpy(old, node_slot.node, node_slot.size);

	ret = append_chain(parent, 18, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, node_slot.node, old, node_slot.size);
	KUNIT_EXPECT_NULL(test, head);
	KUNIT_EXPECT_NULL(test, tail);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_publish_append_root(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = append_chain(NULL, 17, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, root.children, child_array.array);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, entries[0]), head);
	KUNIT_EXPECT_PTR_EQ(test, head, tail);
}

static void stackdepot_trie_publish_append_parent(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long old_entries[] = { 0x2000UL };
	unsigned long new_entries[] = { 0x3000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot new_slot;
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *new_head = NULL;
	const void *new_tail = NULL;
	unsigned int used = 0;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	trie_node_slot_alloc(test, &new_slot, new_entries, ARRAY_SIZE(new_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = append_chain(parent, 18, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head, &old_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(NULL, parent, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = append_chain(parent, 19, new_entries, ARRAY_SIZE(new_entries),
			   &new_slot, 1, NULL, 0, NULL, 0, &new_head, &new_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(NULL, parent, new_head, new_array.array,
			     new_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array.array, old_entries[0]),
			    old_head);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array.array, new_entries[0]),
			    new_head);
	KUNIT_EXPECT_PTR_EQ(test, old_head, old_tail);
	KUNIT_EXPECT_PTR_EQ(test, new_head, new_tail);
}

static void stackdepot_trie_publish_append_root_replaces_array(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL };
	unsigned long new_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot dup_array;
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot dup_slot;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot new_slot;
	struct stack_depot_trie_root root = {};
	const void *dup_head = NULL;
	const void *dup_tail = NULL;
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *new_head = NULL;
	const void *new_tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	trie_node_slot_alloc(test, &dup_slot, old_entries, ARRAY_SIZE(old_entries));
	trie_node_slot_alloc(test, &new_slot, new_entries, ARRAY_SIZE(new_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	dup_array.size = __stack_depot_trie_child_array_size(2);
	dup_array.array = kunit_kzalloc(test, dup_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, dup_array.array);
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = append_chain(NULL, 21, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head, &old_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = append_chain(NULL, 22, old_entries, ARRAY_SIZE(old_entries),
			   &dup_slot, 1, NULL, 0, NULL, 0, &dup_head, &dup_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, dup_head, dup_array.array,
			     dup_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);

	ret = append_chain(NULL, 23, new_entries, ARRAY_SIZE(new_entries),
			   &new_slot, 1, NULL, 0, NULL, 0, &new_head, &new_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, new_head, new_array.array,
			     new_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, root.children, new_array.array);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, old_entries[0]),
			    old_head);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, new_entries[0]),
			    new_head);
	KUNIT_EXPECT_PTR_EQ(test, old_head, old_tail);
	KUNIT_EXPECT_PTR_EQ(test, dup_head, dup_tail);
	KUNIT_EXPECT_PTR_EQ(test, new_head, new_tail);
}

static void stackdepot_trie_publish_append_rejects_bad_inputs(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = append_chain(parent, 20, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, head, child_array.array,
			     child_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = publish_append(NULL, parent, NULL, child_array.array,
			     child_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = publish_append(NULL, parent, head, node_slot.node, node_slot.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_lookup_step_root(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	unsigned long longer[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long partial[] = { 0x1000UL, 0x2222UL };
	unsigned long missing[] = { 0x9000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	ret = lookup_step(&root, NULL, missing, ARRAY_SIZE(missing), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_APPEND);
	KUNIT_EXPECT_NULL(test, lookup.node);
	KUNIT_EXPECT_EQ(test, lookup.matched, 0U);

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = append_chain(NULL, 24, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = lookup_step(&root, NULL, entries, ARRAY_SIZE(entries), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.parent, NULL);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, head);
	KUNIT_EXPECT_EQ(test, lookup.matched, (unsigned int)ARRAY_SIZE(entries));

	ret = lookup_step(&root, NULL, longer, ARRAY_SIZE(longer), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_DESCEND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, head);
	KUNIT_EXPECT_EQ(test, lookup.matched, (unsigned int)ARRAY_SIZE(entries));

	ret = lookup_step(&root, NULL, partial, ARRAY_SIZE(partial), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_SPLIT);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, head);
	KUNIT_EXPECT_EQ(test, lookup.matched, 1U);

	ret = lookup_step(&root, NULL, missing, ARRAY_SIZE(missing), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_APPEND);
	KUNIT_EXPECT_NULL(test, lookup.node);
}

static void stackdepot_trie_lookup_step_parent_promote(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	void *child;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), parent, 0,
			&child);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = publish_append(NULL, parent, child, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = lookup_step(NULL, parent, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_PROMOTE);
	KUNIT_EXPECT_PTR_EQ(test, lookup.parent, parent);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, child);
	KUNIT_EXPECT_EQ(test, lookup.matched,
			(unsigned int)ARRAY_SIZE(child_entries));

	ret = lookup_step(&root, parent, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = lookup_step(NULL, NULL, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = lookup_step(NULL, parent, NULL, ARRAY_SIZE(child_entries), &lookup);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = lookup_step(NULL, parent, child_entries, 0, &lookup);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = lookup_step(NULL, parent, child_entries, ARRAY_SIZE(child_entries),
			  NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_lookup_step_accepts_reparented_child(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot child_slot;
	struct stack_depot_trie_lookup lookup;
	void *old_parent;
	void *new_parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&old_parent);
	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 8,
			&new_parent);
	trie_node_slot_alloc(test, &child_slot, child_entries,
			     ARRAY_SIZE(child_entries));
	KUNIT_ASSERT_EQ(test,
			tnode_init(child_slot.node, child_slot.size, old_parent, 9,
				   child_entries, ARRAY_SIZE(child_entries), NULL, 0),
			0);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = publish_append(NULL, old_parent, child_slot.node, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_ASSERT_EQ(test,
			tnode_init(child_slot.node, child_slot.size, new_parent, 9,
				   child_entries, ARRAY_SIZE(child_entries), NULL, 0),
			0);

	ret = lookup_step(NULL, old_parent, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.parent, old_parent);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, child_slot.node);
	KUNIT_EXPECT_EQ(test, lookup.matched,
			(unsigned int)ARRAY_SIZE(child_entries));
}

static void stackdepot_trie_find_leaf_root(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = append_chain(NULL, 61, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, entries, ARRAY_SIZE(entries)),
			    head);
	KUNIT_EXPECT_NULL(test, find_leaf(NULL, entries, ARRAY_SIZE(entries)));
	KUNIT_EXPECT_NULL(test, find_leaf(&root, NULL, ARRAY_SIZE(entries)));
	KUNIT_EXPECT_NULL(test, find_leaf(&root, entries, 0));
}

static void stackdepot_trie_find_leaf_descends(struct kunit *test)
{
	unsigned long prefix_entries[] = { 0x1000UL };
	unsigned long full_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot prefix_slot;
	struct stack_depot_trie_node_slot child_slot;
	struct stack_depot_trie_root root = {};
	const void *prefix = NULL;
	const void *child = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &prefix_slot, prefix_entries,
			     ARRAY_SIZE(prefix_entries));
	trie_node_slot_alloc(test, &child_slot, &full_entries[1], 1);
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 62, prefix_entries,
			    ARRAY_SIZE(prefix_entries), &prefix_slot, 1, NULL, 0,
			    NULL, 0, root_array.array, root_array.size, &prefix,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 63, full_entries, ARRAY_SIZE(full_entries),
			    &child_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &child, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, prefix_entries,
					    ARRAY_SIZE(prefix_entries)), prefix);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, full_entries,
					    ARRAY_SIZE(full_entries)), child);
}

static void stackdepot_trie_find_leaf_accepts_reparented_child(struct kunit *test)
{
	unsigned long child_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long desc_entries[] = { 0x4000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	unsigned long old_stack[] = { 0x1000UL, 0x2000UL, 0x4000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_node_slot desc_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_root root = {};
	const void *desc_head = NULL;
	const void *desc_tail = NULL;
	const void *new_tail = NULL;
	const void *prefix = NULL;
	unsigned int used = 0;
	void *child;
	int ret;

	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), NULL, 0,
			&child);
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	ret = publish_append(&root, NULL, child, root_array.array,
			     root_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	trie_node_slot_alloc(test, &desc_slot, desc_entries,
			     ARRAY_SIZE(desc_entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = append_chain(child, 3, desc_entries, ARRAY_SIZE(desc_entries),
			   &desc_slot, 1, NULL, 0, NULL, 0, &desc_head,
			   &desc_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(NULL, child, desc_head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	trie_node_slot_alloc(test, &node_slots[0], child_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &child_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	split_array.size = __stack_depot_trie_child_array_size(2);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);
	ret = split_subtree(child, 1, 4, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &split_array, 1,
			    NULL, 0, &prefix, &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, old_stack, ARRAY_SIZE(old_stack)),
			    desc_tail);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, node_slots[2].node);
	KUNIT_EXPECT_PTR_EQ(test, prefix, node_slots[0].node);
}

static void stackdepot_trie_find_leaf_misses(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	unsigned long split_miss[] = { 0x1000UL, 0x2222UL };
	unsigned long append_miss[] = { 0x3000UL };
	unsigned long prefix_miss[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = append_chain(NULL, 64, entries, ARRAY_SIZE(entries), &node_slot, 1,
			   NULL, 0, NULL, 0, &head, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_NULL(test, find_leaf(&root, split_miss,
					  ARRAY_SIZE(split_miss)));
	KUNIT_EXPECT_NULL(test, find_leaf(&root, append_miss,
					  ARRAY_SIZE(append_miss)));
	KUNIT_EXPECT_NULL(test, find_leaf(&root, prefix_miss,
					  ARRAY_SIZE(prefix_miss)));
}

static void stackdepot_trie_find_leaf_rejects_bad_parent(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long wrong_parent_entries[] = { 0x1111UL };
	unsigned long full_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot parent_slot;
	struct stack_depot_trie_node_slot child_slot;
	struct stack_depot_trie_root root = {};
	void *wrong_parent;
	const void *parent = NULL;
	const void *child = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &parent_slot, parent_entries,
			     ARRAY_SIZE(parent_entries));
	trie_node_slot_alloc(test, &child_slot, &full_entries[1], 1);
	trie_node_alloc(test, wrong_parent_entries, ARRAY_SIZE(wrong_parent_entries),
			NULL, 66, &wrong_parent);
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 67, parent_entries,
			    ARRAY_SIZE(parent_entries), &parent_slot, 1, NULL, 0,
			    NULL, 0, root_array.array, root_array.size, &parent,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 68, full_entries, ARRAY_SIZE(full_entries),
			    &child_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &child, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = tnode_init(child_slot.node, child_slot.size, wrong_parent, 68,
			 &full_entries[1], 1, NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_NULL(test, find_leaf(&root, full_entries,
					  ARRAY_SIZE(full_entries)));
}

static void stackdepot_trie_insert_append_root(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 31, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, tail, node_slot.node);
	KUNIT_EXPECT_EQ(test, used, 1U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, child_array.array);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, entries[0]),
			    node_slot.node);
}

static void stackdepot_trie_insert_append_prepare_root(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	struct stackdepot_trie_prepare_ctx ctx = {
		.test = test,
		.visible = &root.children,
		.expected_visible = NULL,
		.expected_leaf_id = { 69 },
		.nr_expected = 1,
	};
	struct stack_depot_trie_publish_prepare prepare = {
		.fn = stackdepot_trie_prepare,
		.ctx = &ctx,
	};
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	ctx.expected_leaf[0] = node_slot.node;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append_prepare(&root, NULL, 69, entries, ARRAY_SIZE(entries),
				    &node_slot, 1, NULL, 0, NULL, 0,
				    child_array.array, child_array.size,
				    &prepare, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, child_array.array);
	KUNIT_EXPECT_PTR_EQ(test, tail, node_slot.node);
	KUNIT_EXPECT_EQ(test, used, 1U);
}

static void stackdepot_trie_insert_append_prepare_failure(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	struct stackdepot_trie_prepare_ctx ctx = {
		.test = test,
		.visible = &root.children,
		.expected_visible = NULL,
		.expected_leaf_id = { 70 },
		.nr_expected = 1,
		.ret = -EAGAIN,
	};
	struct stack_depot_trie_publish_prepare prepare = {
		.fn = stackdepot_trie_prepare,
		.ctx = &ctx,
	};
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	ctx.expected_leaf[0] = node_slot.node;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append_prepare(&root, NULL, 70, entries, ARRAY_SIZE(entries),
				    &node_slot, 1, NULL, 0, NULL, 0,
				    child_array.array, child_array.size,
				    &prepare, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_prepare_promote_failure(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	struct stackdepot_trie_prepare_ctx ctx = {
		.test = test,
		.visible = &root.children,
		.expected_leaf_id = { 72 },
		.nr_expected = 1,
		.ret = -EAGAIN,
	};
	struct stack_depot_trie_publish_prepare prepare = {
		.fn = stackdepot_trie_prepare,
		.ctx = &ctx,
	};
	const void *children[1];
	const void *tail = (const void *)1;
	unsigned int used = 99;
	void *child;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &child);
	children[0] = child;
	old_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = child_array_init(old_array.array, old_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = old_array.array;
	ctx.expected_visible = old_array.array;
	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	ctx.expected_leaf[0] = node_slot.node;
	new_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = insert_append_prepare(&root, NULL, 72, entries, ARRAY_SIZE(entries),
				    &node_slot, 1, NULL, 0, NULL, 0,
				    new_array.array, new_array.size,
				    &prepare, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_prepare_split(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_child_array_slot replace_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_root root = {};
	struct stackdepot_trie_prepare_ctx ctx = {
		.test = test,
		.visible = &root.children,
		.expected_leaf_id = { 73, 74 },
		.nr_expected = 2,
	};
	struct stack_depot_trie_publish_prepare prepare = {
		.fn = stackdepot_trie_prepare,
		.ctx = &ctx,
	};
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *new_tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 73, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx.expected_visible = old_array.array;

	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	ctx.expected_leaf[0] = node_slots[1].node;
	ctx.expected_leaf[1] = node_slots[2].node;
	split_array.size = __stack_depot_trie_child_array_size(2);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);
	replace_array.size = __stack_depot_trie_child_array_size(1);
	replace_array.array = kunit_kzalloc(test, replace_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, replace_array.array);

	ret = insert_append_prepare(&root, NULL, 74, new_entries,
				    ARRAY_SIZE(new_entries), node_slots,
				    ARRAY_SIZE(node_slots), &split_array, 1,
				    NULL, 0, replace_array.array,
				    replace_array.size, &prepare, &new_tail,
				    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, replace_array.array);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, node_slots[2].node);
}

static void stackdepot_trie_insert_append_prepare_split_failure(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_child_array_slot replace_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_root root = {};
	const void *found;
	struct stackdepot_trie_prepare_ctx ctx = {
		.test = test,
		.visible = &root.children,
		.expected_leaf_id = { 75, 76 },
		.nr_expected = 2,
		.ret = -EAGAIN,
	};
	struct stack_depot_trie_publish_prepare prepare = {
		.fn = stackdepot_trie_prepare,
		.ctx = &ctx,
	};
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *new_tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 75, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ctx.expected_visible = old_array.array;

	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	ctx.expected_leaf[0] = node_slots[1].node;
	ctx.expected_leaf[1] = node_slots[2].node;
	split_array.size = __stack_depot_trie_child_array_size(2);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);
	replace_array.size = __stack_depot_trie_child_array_size(1);
	replace_array.array = kunit_kzalloc(test, replace_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, replace_array.array);
	new_tail = (const void *)1;
	used = 99;

	ret = insert_append_prepare(&root, NULL, 76, new_entries,
				    ARRAY_SIZE(new_entries), node_slots,
				    ARRAY_SIZE(node_slots), &split_array, 1,
				    NULL, 0, replace_array.array,
				    replace_array.size, &prepare, &new_tail,
				    &used);
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
	KUNIT_EXPECT_EQ(test, ctx.calls, 1U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);
	KUNIT_EXPECT_PTR_EQ(test, find_leaf(&root, old_entries,
					    ARRAY_SIZE(old_entries)), old_tail);
	found = find_leaf(&root, new_entries, ARRAY_SIZE(new_entries));
	KUNIT_EXPECT_NULL(test, found);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_parent(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long old_entries[] = { 0x2000UL };
	unsigned long new_entries[] = { 0x3000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot new_slot;
	struct stack_depot_trie_lookup lookup;
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *new_tail = NULL;
	unsigned int used = 0;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	trie_node_slot_alloc(test, &new_slot, new_entries, ARRAY_SIZE(new_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = append_chain(parent, 32, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head, &old_tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(NULL, parent, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = insert_append(NULL, parent, 33, new_entries, ARRAY_SIZE(new_entries),
			    &new_slot, 1, NULL, 0, NULL, 0, new_array.array,
			    new_array.size, &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = lookup_step(NULL, parent, old_entries, ARRAY_SIZE(old_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, old_head);
	ret = lookup_step(NULL, parent, new_entries, ARRAY_SIZE(new_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, new_tail);
	KUNIT_EXPECT_EQ(test, used, 1U);
}

static void stackdepot_trie_insert_append_descends_one_level(struct kunit *test)
{
	unsigned long prefix_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	unsigned long stack_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot prefix_slot;
	struct stack_depot_trie_node_slot child_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(stack_entries)] = {};
	const void *prefix = NULL;
	const void *tail = NULL;
	unsigned int fetched;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &prefix_slot, prefix_entries,
			     ARRAY_SIZE(prefix_entries));
	trie_node_slot_alloc(test, &child_slot, child_entries,
			     ARRAY_SIZE(child_entries));
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 47, prefix_entries,
			    ARRAY_SIZE(prefix_entries), &prefix_slot, 1, NULL, 0,
			    NULL, 0, root_array.array, root_array.size, &prefix,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 48, stack_entries,
			    ARRAY_SIZE(stack_entries), &child_slot, 1, NULL, 0,
			    NULL, 0, child_array.array, child_array.size, &tail,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 1U);
	ret = lookup_step(NULL, prefix, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, tail);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(stack_entries));
	KUNIT_EXPECT_MEMEQ(test, out, stack_entries, sizeof(stack_entries));
}

static void stackdepot_trie_insert_append_descends_multiple_levels(struct kunit *test)
{
	unsigned long first_entries[] = { 0x1000UL };
	unsigned long second_entries[] = { 0x2000UL };
	unsigned long tail_entries[] = { 0x3000UL };
	unsigned long second_stack[] = { 0x1000UL, 0x2000UL };
	unsigned long full_stack[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot first_array;
	struct stack_depot_trie_child_array_slot second_array;
	struct stack_depot_trie_child_array_slot third_array;
	struct stack_depot_trie_node_slot first_slot;
	struct stack_depot_trie_node_slot second_slot;
	struct stack_depot_trie_node_slot third_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(full_stack)] = {};
	const void *first = NULL;
	const void *second = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	unsigned int fetched;
	int ret;

	trie_node_slot_alloc(test, &first_slot, first_entries,
			     ARRAY_SIZE(first_entries));
	trie_node_slot_alloc(test, &second_slot, second_entries,
			     ARRAY_SIZE(second_entries));
	trie_node_slot_alloc(test, &third_slot, tail_entries,
			     ARRAY_SIZE(tail_entries));
	first_array.size = __stack_depot_trie_child_array_size(1);
	first_array.array = kunit_kzalloc(test, first_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, first_array.array);
	second_array.size = __stack_depot_trie_child_array_size(1);
	second_array.array = kunit_kzalloc(test, second_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, second_array.array);
	third_array.size = __stack_depot_trie_child_array_size(1);
	third_array.array = kunit_kzalloc(test, third_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, third_array.array);

	ret = insert_append(&root, NULL, 55, first_entries,
			    ARRAY_SIZE(first_entries), &first_slot, 1, NULL, 0,
			    NULL, 0, first_array.array, first_array.size, &first,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 56, second_stack, ARRAY_SIZE(second_stack),
			    &second_slot, 1, NULL, 0, NULL, 0,
			    second_array.array, second_array.size, &second, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 57, full_stack, ARRAY_SIZE(full_stack),
			    &third_slot, 1, NULL, 0, NULL, 0, third_array.array,
			    third_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 1U);
	ret = lookup_step(NULL, second, tail_entries, ARRAY_SIZE(tail_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, tail);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(full_stack));
	KUNIT_EXPECT_MEMEQ(test, out, full_stack, sizeof(full_stack));
}

static void stackdepot_trie_insert_append_descend_rejects_sibling_overlap(struct kunit *test)
{
	unsigned long prefix_entries[] = { 0x1000UL };
	unsigned long sibling_entries[] = { 0x9000UL };
	unsigned long stack_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot sibling_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot prefix_slot;
	struct stack_depot_trie_node_slot sibling_slot;
	struct stack_depot_trie_root root = {};
	struct stack_depot_trie_lookup lookup;
	const void *prefix = NULL;
	const void *sibling = NULL;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &prefix_slot, prefix_entries,
			     ARRAY_SIZE(prefix_entries));
	trie_node_slot_alloc(test, &sibling_slot, sibling_entries,
			     ARRAY_SIZE(sibling_entries));
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	sibling_array.size = __stack_depot_trie_child_array_size(2);
	sibling_array.array = kunit_kzalloc(test, sibling_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, sibling_array.array);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 49, prefix_entries,
			    ARRAY_SIZE(prefix_entries), &prefix_slot, 1, NULL, 0,
			    NULL, 0, root_array.array, root_array.size, &prefix,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_append(&root, NULL, 50, sibling_entries,
			    ARRAY_SIZE(sibling_entries), &sibling_slot, 1, NULL, 0,
			    NULL, 0, sibling_array.array, sibling_array.size,
			    &sibling, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	used = 99;

	ret = insert_append(&root, NULL, 51, stack_entries,
			    ARRAY_SIZE(stack_entries), &sibling_slot, 1, NULL, 0,
			    NULL, 0, child_array.array, child_array.size, &tail,
			    &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
	ret = lookup_step(&root, NULL, sibling_entries, ARRAY_SIZE(sibling_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, sibling);
}

static void stackdepot_trie_insert_append_promotes_internal(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot promote_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	const void *children[1];
	const void *tail = (const void *)1;
	unsigned int fetched;
	unsigned int used = 99;
	void *old_child;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &old_child);
	children[0] = old_child;
	old_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = child_array_init(old_array.array, old_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = old_array.array;
	trie_node_slot_alloc(test, &promote_slot, entries, ARRAY_SIZE(entries));
	new_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = insert_append(&root, NULL, 58, entries, ARRAY_SIZE(entries),
			    &promote_slot, 1, NULL, 0, NULL, 0, new_array.array,
			    new_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, root.children, new_array.array);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, entries[0]), tail);
	KUNIT_EXPECT_PTR_EQ(test, tail, promote_slot.node);
	KUNIT_EXPECT_EQ(test, used, 1U);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
	ret = lookup_step(&root, NULL, entries, ARRAY_SIZE(entries), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, tail);
}

static void stackdepot_trie_insert_append_descends_to_promote(struct kunit *test)
{
	unsigned long prefix_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	unsigned long stack_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot promote_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(stack_entries)] = {};
	const void *root_children[1];
	const void *tail = (const void *)1;
	unsigned int fetched;
	unsigned int used = 99;
	void *child;
	void *prefix;
	int ret;

	trie_node_alloc(test, prefix_entries, ARRAY_SIZE(prefix_entries), NULL, 0,
			&prefix);
	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), prefix, 0,
			&child);
	root_children[0] = prefix;
	root_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(root_children));
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	ret = child_array_init(root_array.array, root_array.size, root_children,
			       ARRAY_SIZE(root_children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = root_array.array;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = publish_append(NULL, prefix, child, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	trie_node_slot_alloc(test, &promote_slot, child_entries,
			     ARRAY_SIZE(child_entries));
	new_array.size = __stack_depot_trie_child_array_size(1);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = insert_append(&root, NULL, 61, stack_entries, ARRAY_SIZE(stack_entries),
			    &promote_slot, 1, NULL, 0, NULL, 0, new_array.array,
			    new_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, root.children, root_array.array);
	ret = lookup_step(NULL, prefix, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, tail);
	KUNIT_EXPECT_EQ(test, used, 1U);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(stack_entries));
	KUNIT_EXPECT_MEMEQ(test, out, stack_entries, sizeof(stack_entries));
}

static void stackdepot_trie_insert_append_promotes_with_children(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot promote_slot;
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long expected[] = { 0x1000UL, 0x2000UL };
	unsigned long out[ARRAY_SIZE(expected)] = {};
	const void *root_children[1];
	const void *tail = NULL;
	unsigned int fetched;
	unsigned int used = 99;
	void *child;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 0,
			&parent);
	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), parent, 59,
			&child);
	root_children[0] = parent;
	root_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(root_children));
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	ret = child_array_init(root_array.array, root_array.size, root_children,
			       ARRAY_SIZE(root_children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = root_array.array;
	new_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(root_children));
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);
	ret = publish_append(NULL, parent, child, new_array.array, new_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	trie_node_slot_alloc(test, &promote_slot, parent_entries,
			     ARRAY_SIZE(parent_entries));
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = insert_append(&root, NULL, 60, parent_entries,
			    ARRAY_SIZE(parent_entries), &promote_slot, 1, NULL, 0,
			    NULL, 0, new_array.array, new_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, root.children, new_array.array);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, parent_entries[0]),
			    tail);
	ret = lookup_step(NULL, tail, child_entries, ARRAY_SIZE(child_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, child);
	KUNIT_EXPECT_EQ(test, used, 1U);
	fetched = tfetch(child, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_insert_append_splits_frame_runs(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
		0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x3000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
		0xffff888000001000UL,
		0xffffffff81003000UL,
#endif
	};
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_child_array_slot child_slots[2];
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	u32 write_scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	const void *tail = NULL;
	unsigned int used = 0;
	unsigned int fetched;
	unsigned int i;
	int ret;

	trie_node_slot_alloc(test, &node_slots[0], entries, 2);
	trie_node_slot_alloc(test, &node_slots[1], &entries[2], 1);
	trie_node_slot_alloc(test, &node_slots[2], &entries[3], 1);

	for (i = 0; i < ARRAY_SIZE(child_slots); i++) {
		child_slots[i].size = __stack_depot_trie_child_array_size(1);
		child_slots[i].array = kunit_kzalloc(test, child_slots[i].size, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, child_slots[i].array);
	}
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);

	ret = insert_append(&root, NULL, 42, entries, ARRAY_SIZE(entries),
			    node_slots, ARRAY_SIZE(node_slots), child_slots,
			    ARRAY_SIZE(child_slots), write_scratch,
			    ARRAY_SIZE(write_scratch), root_array.array,
			    root_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 3U);
	KUNIT_EXPECT_PTR_EQ(test, tail, node_slots[2].node);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(root.children, entries[0]),
			    node_slots[0].node);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}
#endif

static void stackdepot_trie_insert_append_splits_child(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_child_array_slot replace_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(old_entries)] = {};
	const void *old_head = NULL;
	const void *old_tail;
	const void *new_tail = NULL;
	const void *prefix;
	unsigned int fetched;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 1, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	split_array.size = __stack_depot_trie_child_array_size(2);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);
	replace_array.size = __stack_depot_trie_child_array_size(1);
	replace_array.array = kunit_kzalloc(test, replace_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, replace_array.array);
	used = 99;

	ret = insert_append(&root, NULL, 2, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &split_array, 1,
			    NULL, 0, replace_array.array, replace_array.size,
			    &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 3U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, replace_array.array);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, node_slots[2].node);

	ret = lookup_step(&root, NULL, old_entries, ARRAY_SIZE(old_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_DESCEND);
	prefix = lookup.node;
	ret = lookup_step(NULL, prefix, &old_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	old_tail = lookup.node;
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, old_entries, sizeof(old_entries));

	memset(out, 0, sizeof(out));
	ret = lookup_step(&root, NULL, new_entries, ARRAY_SIZE(new_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_DESCEND);
	ret = lookup_step(NULL, lookup.node, &new_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, new_tail);
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, new_entries, sizeof(new_entries));
}

static void stackdepot_trie_insert_append_splits_prefix_leaf(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_child_array_slot replace_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot node_slots[2];
	struct stack_depot_trie_lookup lookup;
	struct stack_depot_trie_root root = {};
	unsigned long out[ARRAY_SIZE(old_entries)] = {};
	const void *old_head = NULL;
	const void *old_tail;
	const void *new_tail = NULL;
	unsigned int fetched;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 1, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	split_array.size = __stack_depot_trie_child_array_size(1);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);
	replace_array.size = __stack_depot_trie_child_array_size(1);
	replace_array.array = kunit_kzalloc(test, replace_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, replace_array.array);
	used = 99;

	ret = insert_append(&root, NULL, 2, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &split_array, 1,
			    NULL, 0, replace_array.array, replace_array.size,
			    &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 2U);
	KUNIT_EXPECT_PTR_EQ(test, root.children, replace_array.array);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, node_slots[0].node);
	ret = lookup_step(&root, NULL, new_entries, ARRAY_SIZE(new_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, new_tail);
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 1U);
	KUNIT_EXPECT_MEMEQ(test, out, new_entries, sizeof(new_entries));

	ret = lookup_step(&root, NULL, old_entries, ARRAY_SIZE(old_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_DESCEND);
	ret = lookup_step(NULL, lookup.node, &old_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	memset(out, 0, sizeof(out));
	fetched = tfetch(lookup.node, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, old_entries, sizeof(old_entries));
}

static void stackdepot_trie_insert_plan_append(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_frame_run run;
	struct stack_depot_trie_root root = {};
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), &node_slot,
			  1, &child_slot, 1, &publish_size, &used,
			  &child_used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, node_slot.node);
	KUNIT_EXPECT_EQ(test, node_slot.size, __stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, used, 1U);
	KUNIT_EXPECT_EQ(test, child_used, 0U);
	KUNIT_EXPECT_EQ(test, publish_size, __stack_depot_trie_child_array_size(1));
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_insert_plan_mixed_append(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		0x1000UL,
#else
		0xffffffff81001000UL,
		0xffff888000001000UL,
#endif
	};
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot node_slots[2];
	struct stack_depot_frame_run first_run;
	struct stack_depot_frame_run second_run;
	struct stack_depot_trie_root root = {};
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &first_run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = frame_run_init(&entries[first_run.nr_entries],
			     ARRAY_SIZE(entries) - first_run.nr_entries,
			     &second_run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), node_slots,
			  ARRAY_SIZE(node_slots), &child_slot, 1, &publish_size,
			  &used, &child_used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 2U);
	KUNIT_EXPECT_EQ(test, child_used, 1U);
	KUNIT_EXPECT_EQ(test, node_slots[0].size,
			__stack_depot_trie_node_size(&first_run));
	KUNIT_EXPECT_EQ(test, node_slots[1].size,
			__stack_depot_trie_node_size(&second_run));
	KUNIT_EXPECT_EQ(test, child_slot.size,
			__stack_depot_trie_child_array_size(1));
	KUNIT_EXPECT_EQ(test, publish_size, __stack_depot_trie_child_array_size(1));
}
#endif

static void stackdepot_trie_insert_plan_promote(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_frame_run run;
	struct stack_depot_trie_root root = {};
	const void *children[1];
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	void *child;
	int ret;

	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &child);
	children[0] = child;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = child_array_init(child_array.array, child_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = child_array.array;

	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), &node_slot,
			  1, NULL, 0, &publish_size, &used, &child_used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_NULL(test, node_slot.node);
	KUNIT_EXPECT_EQ(test, node_slot.size, __stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, used, 1U);
	KUNIT_EXPECT_EQ(test, child_used, 0U);
	KUNIT_EXPECT_EQ(test, publish_size, __stack_depot_trie_child_array_size(1));
}

static void stackdepot_trie_insert_plan_promote_rejects_empty_slots(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot = {
		.node = (void *)1,
		.size = 99,
	};
	struct stack_depot_trie_root root = {};
	const void *children[1];
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	void *child;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 0, &child);
	children[0] = child;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = child_array_init(child_array.array, child_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = child_array.array;

	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), &node_slot,
			  0, NULL, 0, &publish_size, &used, &child_used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, node_slot.node, (void *)1);
	KUNIT_EXPECT_EQ(test, node_slot.size, (size_t)99);
}

static void stackdepot_trie_insert_plan_split(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_frame_run run;
	struct stack_depot_trie_root root = {};
	const void *old_head = NULL;
	const void *old_tail = NULL;
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 1, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = frame_run_init(new_entries, 1, &run);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = insert_plan(&root, NULL, new_entries, ARRAY_SIZE(new_entries),
			  node_slots, ARRAY_SIZE(node_slots), &child_slot, 1,
			  &publish_size, &used, &child_used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 3U);
	KUNIT_EXPECT_EQ(test, child_used, 1U);
	KUNIT_EXPECT_EQ(test, node_slots[0].size,
			__stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, node_slots[1].size,
			__stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, node_slots[2].size,
			__stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, child_slot.size,
			__stack_depot_trie_child_array_size(2));
	KUNIT_EXPECT_EQ(test, publish_size, __stack_depot_trie_child_array_size(1));
}

static void stackdepot_trie_insert_plan_descends(struct kunit *test)
{
	unsigned long prefix_entries[] = { 0x1000UL };
	unsigned long stack_entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_child_array_slot root_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_node_slot prefix_slot;
	struct stack_depot_frame_run run;
	struct stack_depot_trie_root root = {};
	const void *prefix = NULL;
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	int ret;

	trie_node_slot_alloc(test, &prefix_slot, prefix_entries,
			     ARRAY_SIZE(prefix_entries));
	root_array.size = __stack_depot_trie_child_array_size(1);
	root_array.array = kunit_kzalloc(test, root_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, root_array.array);
	ret = insert_append(&root, NULL, 75, prefix_entries,
			    ARRAY_SIZE(prefix_entries), &prefix_slot, 1, NULL, 0,
			    NULL, 0, root_array.array, root_array.size, &prefix,
			    &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = frame_run_init(&stack_entries[1], 1, &run);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = insert_plan(&root, NULL, stack_entries, ARRAY_SIZE(stack_entries),
			  &node_slot, 1, NULL, 0, &publish_size, &used,
			  &child_used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 1U);
	KUNIT_EXPECT_EQ(test, child_used, 0U);
	KUNIT_EXPECT_EQ(test, node_slot.size, __stack_depot_trie_node_size(&run));
	KUNIT_EXPECT_EQ(test, publish_size, __stack_depot_trie_child_array_size(1));
}

static void stackdepot_trie_insert_plan_rejects_existing_leaf(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *tail = NULL;
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = insert_append(&root, NULL, 76, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), &node_slot,
			  1, NULL, 0, &publish_size, &used, &child_used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_insert_plan_rejects_bad_child(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *children[1];
	unsigned int child_used = 99;
	unsigned int used = 99;
	size_t publish_size = 0;
	void *bad_parent;
	void *child;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 77, &bad_parent);
	trie_node_alloc(test, entries, ARRAY_SIZE(entries), bad_parent, 78, &child);
	children[0] = child;
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = child_array_init(child_array.array, child_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = child_array.array;

	ret = insert_plan(&root, NULL, entries, ARRAY_SIZE(entries), &node_slot,
			  1, NULL, 0, &publish_size, &used, &child_used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_insert_append_rejects_existing_child(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot dup_slot;
	struct stack_depot_trie_root root = {};
	unsigned char *old;
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, entries, ARRAY_SIZE(entries));
	trie_node_slot_alloc(test, &dup_slot, entries, ARRAY_SIZE(entries));
	old = kunit_kzalloc(test, dup_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(dup_slot.node, 0xaa, dup_slot.size);
	memcpy(old, dup_slot.node, dup_slot.size);
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = append_chain(NULL, 34, entries, ARRAY_SIZE(entries), &old_slot, 1,
			   NULL, 0, NULL, 0, &old_head, &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	used = 99;

	ret = insert_append(&root, NULL, 35, entries, ARRAY_SIZE(entries),
			    &dup_slot, 1, NULL, 0, NULL, 0, new_array.array,
			    new_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);
	KUNIT_EXPECT_MEMEQ(test, dup_slot.node, old, dup_slot.size);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_short_array(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(0);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 36, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_zero_frame(struct kunit *test)
{
	unsigned long entries[] = { 0 };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	unsigned char *old;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	old = kunit_kzalloc(test, node_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(node_slot.node, 0xaa, node_slot.size);
	memcpy(old, node_slot.node, node_slot.size);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 39, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_MEMEQ(test, node_slot.node, old, node_slot.size);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_root_with_parent(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *tail = (const void *)1;
	unsigned int used = 99;
	void *parent;
	int ret;

	trie_node_alloc(test, parent_entries, ARRAY_SIZE(parent_entries), NULL, 7,
			&parent);
	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, parent, 37, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_root_slot_alias(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	node_slot.node = &root.children;
	node_slot.size = sizeof(root.children);
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(&root, NULL, 40, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_parent_overlap(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long child_entries[] = { 0x2000UL };
	struct stack_depot_trie_node_slot parent_slot;
	struct stack_depot_trie_node_slot child_slot;
	struct stack_depot_trie_lookup lookup;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	unsigned char *old;
	int ret;

	trie_node_slot_alloc(test, &parent_slot, parent_entries,
			     ARRAY_SIZE(parent_entries));
	ret = tnode_init(parent_slot.node, parent_slot.size, NULL, 7,
			 parent_entries, ARRAY_SIZE(parent_entries), NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	trie_node_slot_alloc(test, &child_slot, child_entries,
			     ARRAY_SIZE(child_entries));
	old = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(child_slot.node, 0xaa, child_slot.size);
	memcpy(old, child_slot.node, child_slot.size);

	ret = insert_append(NULL, parent_slot.node, 41, child_entries,
			    ARRAY_SIZE(child_entries), &child_slot, 1, NULL, 0,
			    NULL, 0, parent_slot.node, parent_slot.size, &tail,
			    &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, child_slot.node, old, child_slot.size);
	ret = lookup_step(NULL, parent_slot.node, child_entries,
			  ARRAY_SIZE(child_entries), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_APPEND);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_parent_cycle(struct kunit *test)
{
	unsigned long parent_entries[] = { 0x1000UL };
	unsigned long entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_node_slot parent_slot;
	struct stack_depot_trie_node_slot node_slot;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &parent_slot, parent_entries,
			     ARRAY_SIZE(parent_entries));
	ret = tnode_init(parent_slot.node, parent_slot.size, NULL, 7,
			 parent_entries, ARRAY_SIZE(parent_entries), NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = tnode_init(parent_slot.node, parent_slot.size, parent_slot.node, 7,
			 parent_entries, ARRAY_SIZE(parent_entries), NULL, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);
	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);

	ret = insert_append(NULL, parent_slot.node, 42, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, child_array.array,
			    child_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_publish_overlap(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	unsigned char *old;
	const void *tail = (const void *)1;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	old = kunit_kzalloc(test, node_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(node_slot.node, 0xaa, node_slot.size);
	memcpy(old, node_slot.node, node_slot.size);

	ret = insert_append(&root, NULL, 38, entries, ARRAY_SIZE(entries),
			    &node_slot, 1, NULL, 0, NULL, 0, node_slot.node,
			    node_slot.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_NULL(test, root.children);
	KUNIT_EXPECT_MEMEQ(test, node_slot.node, old, node_slot.size);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_child_node_overlap(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL };
	unsigned long new_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot new_slot;
	struct stack_depot_trie_root root = {};
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *tail = (const void *)1;
	unsigned char *old;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 43, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	old = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memcpy(old, old_array.array, old_array.size);
	new_slot.node = old_array.array;
	new_slot.size = old_array.size;
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);
	used = 99;

	ret = insert_append(&root, NULL, 44, new_entries, ARRAY_SIZE(new_entries),
			    &new_slot, 1, NULL, 0, NULL, 0, new_array.array,
			    new_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, old_array.array, old, old_array.size);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

static void stackdepot_trie_insert_append_rejects_child_array_overlap(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL };
	unsigned long new_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot old_slot;
	struct stack_depot_trie_node_slot new_slot;
	struct stack_depot_trie_root root = {};
	const void *old_head = NULL;
	const void *old_tail = NULL;
	const void *tail = (const void *)1;
	unsigned char *old;
	unsigned int used = 99;
	int ret;

	trie_node_slot_alloc(test, &old_slot, old_entries, ARRAY_SIZE(old_entries));
	trie_node_slot_alloc(test, &new_slot, new_entries, ARRAY_SIZE(new_entries));
	old_array.size = __stack_depot_trie_child_array_size(1);
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = append_chain(NULL, 45, old_entries, ARRAY_SIZE(old_entries),
			   &old_slot, 1, NULL, 0, NULL, 0, &old_head,
			   &old_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(&root, NULL, old_head, old_array.array,
			     old_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	old = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memcpy(old, old_array.array, old_array.size);
	child_slot.array = old_array.array;
	child_slot.size = old_array.size;
	new_array.size = __stack_depot_trie_child_array_size(2);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);
	used = 99;

	ret = insert_append(&root, NULL, 46, new_entries, ARRAY_SIZE(new_entries),
			    &new_slot, 1, &child_slot, 1, NULL, 0, new_array.array,
			    new_array.size, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, old_array.array, old, old_array.size);
	KUNIT_EXPECT_PTR_EQ(test, root.children, old_array.array);
	KUNIT_EXPECT_PTR_EQ(test, tail, (const void *)1);
	KUNIT_EXPECT_EQ(test, used, 99U);
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_node_compressed_roundtrip(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
#endif
	};
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned int fetched;
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 11, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_trie_node_match_compressed(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
#endif
	};
	unsigned long mismatch[] = {
		entries[0],
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x3000UL,
#else
		0xffffffff81003000UL,
#endif
	};
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 11, &node);
	KUNIT_EXPECT_EQ(test, tmatch(node, entries, ARRAY_SIZE(entries)),
			(unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_EQ(test, tmatch(node, mismatch, ARRAY_SIZE(mismatch)), 1U);
}

static void stackdepot_trie_append_chain_splits_frame_runs(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
		0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x3000UL,
#else
		0xffffffff81001000UL,
		0xffffffff81002000UL,
		0xffff888000001000UL,
		0xffffffff81003000UL,
#endif
	};
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_child_array_slot child_slots[2];
	unsigned long out[ARRAY_SIZE(entries)] = {};
	const void *child;
	u32 write_scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	unsigned int fetched;
	unsigned int i;
	int ret;

	trie_node_slot_alloc(test, &node_slots[0], entries, 2);
	trie_node_slot_alloc(test, &node_slots[1], &entries[2], 1);
	trie_node_slot_alloc(test, &node_slots[2], &entries[3], 1);

	for (i = 0; i < ARRAY_SIZE(child_slots); i++) {
		size_t size;

		child_slots[i].size = __stack_depot_trie_child_array_size(1);
		size = child_slots[i].size;
		child_slots[i].array = kunit_kzalloc(test, size, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, child_slots[i].array);
	}

	ret = append_chain(NULL, 15, entries, ARRAY_SIZE(entries), node_slots,
			   ARRAY_SIZE(node_slots), child_slots, ARRAY_SIZE(child_slots),
			   write_scratch, ARRAY_SIZE(write_scratch), &head, &tail,
			   &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, head, node_slots[0].node);
	KUNIT_EXPECT_PTR_EQ(test, tail, node_slots[2].node);
	KUNIT_EXPECT_EQ(test, used, 3U);
	child = child_array_find(child_slots[0].array, entries[2]);
	KUNIT_EXPECT_PTR_EQ(test, child, node_slots[1].node);
	child = child_array_find(child_slots[1].array, entries[3]);
	KUNIT_EXPECT_PTR_EQ(test, child, node_slots[2].node);
	fetched = tfetch(tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_trie_append_chain_rejects_bad_inputs(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		0x1000UL,
#else
		0xffffffff81001000UL,
		0xffff888000001000UL,
#endif
	};
	struct stack_depot_trie_node_slot node_slots[2];
	struct stack_depot_trie_child_array_slot child_slot;
	u32 write_scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	const void *head = NULL;
	const void *tail = NULL;
	unsigned int used = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slots[0], entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &entries[1], 1);
	child_slot.size = __stack_depot_trie_child_array_size(1);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);

	ret = append_chain(NULL, 16, entries, ARRAY_SIZE(entries), node_slots, 1,
			   &child_slot, 1, write_scratch, ARRAY_SIZE(write_scratch),
			   &head, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = append_chain(NULL, 16, entries, ARRAY_SIZE(entries), node_slots,
			   ARRAY_SIZE(node_slots), NULL, 0, write_scratch,
			   ARRAY_SIZE(write_scratch), &head, &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = append_chain(NULL, 16, entries, ARRAY_SIZE(entries), node_slots,
			   ARRAY_SIZE(node_slots), &child_slot, 1, NULL, 0, &head,
			   &tail, &used);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_node_rejects_compressed_without_scratch(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
#else
		0xffffffff81001000UL,
#endif
	};
	struct stack_depot_frame_run run;
	void *storage;
	size_t size;
	int ret;

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, ARRAY_SIZE(entries), &run), 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	storage = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, storage);
	ret = tnode_init(storage, size, NULL, 1, entries, ARRAY_SIZE(entries),
			 NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}
#endif

static void stackdepot_trie_node_rejects_short_storage(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	struct stack_depot_frame_run run;
	unsigned char storage[sizeof(unsigned long)];
	size_t size;
	int ret;

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, ARRAY_SIZE(entries), &run), 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, sizeof(storage));
	ret = tnode_init(storage, sizeof(storage), NULL, 1, entries,
			 ARRAY_SIZE(entries), NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_node_rejects_mixed_run(struct kunit *test)
{
	unsigned long storage[32];
	u32 write_scratch[CONFIG_STACKDEPOT_MAX_FRAMES];
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		0x1000UL,
#else
		0xffffffff81001000UL,
		0xffff888000001000UL,
#endif
	};
	int ret;

	ret = tnode_init(storage, sizeof(storage), NULL, 1, entries,
			 ARRAY_SIZE(entries), write_scratch,
			 ARRAY_SIZE(write_scratch));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}
#endif

static void stackdepot_trie_fetch_rejects_bad_inputs(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	unsigned long root_entries[] = { 0x3000UL };
	unsigned long out[ARRAY_SIZE(entries)] = { 0xa5a5UL, 0xb6b6UL };
	unsigned long expected[ARRAY_SIZE(out)];
	unsigned int fetched;
	void *node;
	void *root;

	memcpy(expected, out, sizeof(expected));
	trie_node_alloc(test, root_entries, ARRAY_SIZE(root_entries), NULL, 0,
			&root);
	fetched = tfetch(root, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 5, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out) - 1);
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));
	fetched = tfetch(node, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
	memcpy(out, expected, sizeof(out));
	fetched = tfetch(NULL, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));
}

static void stackdepot_trie_child_array_init_find(struct kunit *test)
{
	unsigned long first_entries[] = { 0x1000UL };
	unsigned long second_entries[] = { 0x2000UL };
	unsigned long third_entries[] = { 0x3000UL };
	const void *children[3];
	void *node;
	void *array;
	size_t size;
	int ret;

	trie_node_alloc(test, first_entries, ARRAY_SIZE(first_entries), NULL, 1,
			&node);
	children[0] = node;
	trie_node_alloc(test, second_entries, ARRAY_SIZE(second_entries), NULL, 2,
			&node);
	children[1] = node;
	trie_node_alloc(test, third_entries, ARRAY_SIZE(third_entries), NULL, 3,
			&node);
	children[2] = node;

	size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	array = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, array);
	ret = child_array_init(array, size, children, ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, 0x1000UL), children[0]);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, 0x2000UL), children[1]);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, 0x3000UL), children[2]);
	KUNIT_EXPECT_NULL(test, child_array_find(array, 0x4000UL));
	KUNIT_EXPECT_NULL(test, child_array_find(NULL, 0x1000UL));
}

static void stackdepot_trie_child_array_rejects_unsorted(struct kunit *test)
{
	unsigned long first_entries[] = { 0x2000UL };
	unsigned long second_entries[] = { 0x1000UL };
	const void *children[2];
	void *node;
	void *array;
	size_t size;
	int ret;

	trie_node_alloc(test, first_entries, ARRAY_SIZE(first_entries), NULL, 1,
			&node);
	children[0] = node;
	trie_node_alloc(test, second_entries, ARRAY_SIZE(second_entries), NULL, 2,
			&node);
	children[1] = node;
	size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	array = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, array);
	ret = child_array_init(array, size, children, ARRAY_SIZE(children));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_child_array_init_rejects_child_overlap(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	const void *children[1];
	unsigned char *old;
	void *node;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 1, &node);
	children[0] = node;
	size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memcpy(old, node, size);

	ret = child_array_init(node, size, children, ARRAY_SIZE(children));
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, node, old, size);
}

static void stackdepot_trie_child_array_insert(struct kunit *test)
{
	unsigned long first_entries[] = { 0x1000UL };
	unsigned long second_entries[] = { 0x3000UL };
	unsigned long middle_entries[] = { 0x2000UL };
	const void *children[2];
	void *old_array;
	void *new_array;
	void *middle;
	void *node;
	size_t old_size;
	size_t new_size;
	int ret;

	trie_node_alloc(test, first_entries, ARRAY_SIZE(first_entries), NULL, 1,
			&node);
	children[0] = node;
	trie_node_alloc(test, second_entries, ARRAY_SIZE(second_entries), NULL, 2,
			&node);
	children[1] = node;
	trie_node_alloc(test, middle_entries, ARRAY_SIZE(middle_entries), NULL, 3,
			&middle);
	old_size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	new_size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children) + 1);
	old_array = kunit_kzalloc(test, old_size, GFP_KERNEL);
	new_array = kunit_kzalloc(test, new_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array);
	KUNIT_ASSERT_NOT_NULL(test, new_array);
	KUNIT_ASSERT_EQ(test,
			child_array_init(old_array, old_size, children,
					 ARRAY_SIZE(children)),
			0);

	ret = child_array_insert(old_array, middle, new_array, new_size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array, 0x1000UL), children[0]);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array, 0x2000UL), middle);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array, 0x3000UL), children[1]);
	ret = child_array_insert(old_array, children[0], new_array, new_size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = child_array_insert(old_array, middle, old_array, old_size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_child_array_insert_rejects_child_overlap(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	unsigned char *old;
	void *child;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 1, &child);
	size = __stack_depot_trie_child_array_size(1);
	old = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memcpy(old, child, size);

	ret = child_array_insert(NULL, child, child, size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_MEMEQ(test, child, old, size);
}

static void stackdepot_trie_split_child_array_init_one_child(struct kunit *test)
{
	unsigned long old_entries[] = { 0x2000UL };
	void *old_tail;
	void *array;
	size_t size;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&old_tail);
	size = __stack_depot_trie_child_array_size(1);
	array = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, array);
	ret = split_child_array_init(array, size, old_tail, NULL);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, old_entries[0]), old_tail);
}

static void stackdepot_trie_split_child_array_init_orders_children(struct kunit *test)
{
	unsigned long old_entries[] = { 0x3000UL };
	unsigned long new_entries[] = { 0x1000UL };
	void *new_head;
	void *old_tail;
	void *array;
	size_t size;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&old_tail);
	trie_node_alloc(test, new_entries, ARRAY_SIZE(new_entries), NULL, 2,
			&new_head);
	size = __stack_depot_trie_child_array_size(2);
	array = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, array);
	ret = split_child_array_init(array, size, old_tail, new_head);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, new_entries[0]), new_head);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(array, old_entries[0]), old_tail);
}

static void stackdepot_trie_split_child_array_rejects_bad_inputs(struct kunit *test)
{
	unsigned long old_entries[] = { 0x2000UL };
	unsigned long dup_entries[] = { 0x2000UL };
	unsigned char *old;
	void *old_tail;
	void *dup_tail;
	void *array;
	size_t size;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&old_tail);
	trie_node_alloc(test, dup_entries, ARRAY_SIZE(dup_entries), NULL, 2,
			&dup_tail);
	size = __stack_depot_trie_child_array_size(2);
	array = kunit_kzalloc(test, size, GFP_KERNEL);
	old = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, array);
	KUNIT_ASSERT_NOT_NULL(test, old);
	memset(array, 0xaa, size);
	memcpy(old, array, size);

	KUNIT_EXPECT_EQ(test, split_child_array_init(array, size, NULL, dup_tail),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, split_child_array_init(array, size, old_tail, dup_tail),
			-EINVAL);
	size = __stack_depot_trie_child_array_size(1);
	KUNIT_EXPECT_EQ(test, split_child_array_init(array, size, old_tail, dup_tail),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, split_child_array_init(old_tail, size, old_tail, NULL),
			-EINVAL);
	KUNIT_EXPECT_MEMEQ(test, array, old, size);
}

static void stackdepot_trie_split_tail_plan_raw(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_node_slot node_slot;
	unsigned int nr_runs = 0;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	ret = split_tail_plan(entries, ARRAY_SIZE(entries), &node_slot, 1, NULL, 0,
			      &nr_runs);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, nr_runs, 1U);
}

#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
static void stackdepot_trie_split_tail_plan_mixed_runs(struct kunit *test)
{
	unsigned long entries[] = {
#ifdef CONFIG_ARM64
		arch_stack_depot_frame_text_prefix() | 0x1000UL,
		0x1000UL,
		arch_stack_depot_frame_text_prefix() | 0x2000UL,
#else
		0xffffffff81001000UL,
		0xffff888000001000UL,
		0xffffffff81002000UL,
#endif
	};
	struct stack_depot_trie_child_array_slot child_slots[2];
	struct stack_depot_trie_node_slot node_slots[3];
	unsigned int nr_runs = 0;
	unsigned int i;
	int ret;

	trie_node_slot_alloc(test, &node_slots[0], entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &entries[2], 1);
	for (i = 0; i < ARRAY_SIZE(child_slots); i++) {
		size_t size;

		child_slots[i].size = __stack_depot_trie_child_array_size(1);
		size = child_slots[i].size;
		child_slots[i].array = kunit_kzalloc(test, size, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, child_slots[i].array);
	}

	ret = split_tail_plan(entries, ARRAY_SIZE(entries), node_slots,
			      ARRAY_SIZE(node_slots), child_slots,
			      ARRAY_SIZE(child_slots), &nr_runs);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, nr_runs, 3U);
}
#endif

static void stackdepot_trie_split_tail_plan_rejects_bad_inputs(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL };
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_node_slot short_slot;
	struct stack_depot_frame_run run;
	unsigned int nr_runs = 99;
	int ret;

	trie_node_slot_alloc(test, &node_slot, entries, ARRAY_SIZE(entries));
	ret = frame_run_init(entries, ARRAY_SIZE(entries), &run);
	KUNIT_ASSERT_EQ(test, ret, 0);
	short_slot = node_slot;
	short_slot.size = __stack_depot_trie_node_size(&run) - 1;

	ret = split_tail_plan(NULL, ARRAY_SIZE(entries), &node_slot, 1, NULL, 0,
			      &nr_runs);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = split_tail_plan(entries, 0, &node_slot, 1, NULL, 0, &nr_runs);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = split_tail_plan(entries, ARRAY_SIZE(entries), NULL, 1, NULL, 0,
			      &nr_runs);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = split_tail_plan(entries, ARRAY_SIZE(entries), &node_slot, 1, NULL, 0,
			      NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	ret = split_tail_plan(entries, ARRAY_SIZE(entries), &short_slot, 1, NULL, 0,
			      &nr_runs);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_split_precheck(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL };
	unsigned long new_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *children[1];
	void *old_child;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&old_child);
	trie_node_slot_alloc(test, &node_slot, new_entries, ARRAY_SIZE(new_entries));
	children[0] = old_child;
	old_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = child_array_init(old_array.array, old_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = old_array.array;
	child_slot.size = __stack_depot_trie_child_array_size(1);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);
	new_array.size = __stack_depot_trie_child_array_size(1);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = split_precheck(&root, NULL, &node_slot, 1, &child_slot, 1,
			     new_array.array, new_array.size);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

static void stackdepot_trie_split_precheck_rejects_aliases(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL };
	unsigned long new_entries[] = { 0x2000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *children[1];
	void *old_child;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&old_child);
	trie_node_slot_alloc(test, &node_slot, new_entries, ARRAY_SIZE(new_entries));
	children[0] = old_child;
	old_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = child_array_init(old_array.array, old_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = old_array.array;
	child_slot.size = __stack_depot_trie_child_array_size(1);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);
	new_array.size = __stack_depot_trie_child_array_size(1);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = split_precheck(&root, NULL, &node_slot, 1, &child_slot, 1,
			     old_array.array, old_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	node_slot.node = old_array.array;
	node_slot.size = old_array.size;
	ret = split_precheck(&root, NULL, &node_slot, 1, &child_slot, 1,
			     new_array.array, new_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_split_precheck_rejects_short_array(struct kunit *test)
{
	unsigned long first_entries[] = { 0x1000UL };
	unsigned long second_entries[] = { 0x2000UL };
	unsigned long new_entries[] = { 0x3000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_child_array_slot old_array;
	struct stack_depot_trie_child_array_slot new_array;
	struct stack_depot_trie_node_slot node_slot;
	struct stack_depot_trie_root root = {};
	const void *children[2];
	void *first_child;
	void *second_child;
	int ret;

	trie_node_alloc(test, first_entries, ARRAY_SIZE(first_entries), NULL, 1,
			&first_child);
	trie_node_alloc(test, second_entries, ARRAY_SIZE(second_entries), NULL, 2,
			&second_child);
	trie_node_slot_alloc(test, &node_slot, new_entries, ARRAY_SIZE(new_entries));
	children[0] = first_child;
	children[1] = second_child;
	old_array.size = __stack_depot_trie_child_array_size(ARRAY_SIZE(children));
	old_array.array = kunit_kzalloc(test, old_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, old_array.array);
	ret = child_array_init(old_array.array, old_array.size, children,
			       ARRAY_SIZE(children));
	KUNIT_ASSERT_EQ(test, ret, 0);
	root.children = old_array.array;
	child_slot.size = __stack_depot_trie_child_array_size(1);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);
	new_array.size = __stack_depot_trie_child_array_size(1);
	new_array.array = kunit_kzalloc(test, new_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array.array);

	ret = split_precheck(&root, NULL, &node_slot, 1, &child_slot, 1,
			     new_array.array, new_array.size);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void stackdepot_trie_split_subtree_divergent_tail(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_lookup lookup;
	unsigned long out[ARRAY_SIZE(old_entries)] = {};
	const void *new_tail = NULL;
	const void *old_tail;
	const void *prefix = NULL;
	unsigned int fetched;
	unsigned int used = 99;
	void *child;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&child);
	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	child_slot.size = __stack_depot_trie_child_array_size(2);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);

	ret = split_subtree(child, 1, 2, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &child_slot, 1,
			    NULL, 0, &prefix, &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 3U);
	ret = lookup_step(NULL, prefix, &old_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	old_tail = lookup.node;
	KUNIT_EXPECT_PTR_EQ(test, new_tail, node_slots[2].node);
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, old_entries, sizeof(old_entries));
	memset(out, 0, sizeof(out));
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, new_entries, sizeof(new_entries));
}

static void stackdepot_trie_split_subtree_prefix_leaf(struct kunit *test)
{
	unsigned long old_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long new_entries[] = { 0x1000UL };
	struct stack_depot_trie_child_array_slot child_slot;
	struct stack_depot_trie_node_slot node_slots[2];
	struct stack_depot_trie_lookup lookup;
	unsigned long out[ARRAY_SIZE(old_entries)] = {};
	const void *new_tail = NULL;
	const void *old_tail;
	const void *prefix = NULL;
	unsigned int fetched;
	unsigned int used = 99;
	void *child;
	int ret;

	trie_node_alloc(test, old_entries, ARRAY_SIZE(old_entries), NULL, 1,
			&child);
	trie_node_slot_alloc(test, &node_slots[0], old_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &old_entries[1], 1);
	child_slot.size = __stack_depot_trie_child_array_size(1);
	child_slot.array = kunit_kzalloc(test, child_slot.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_slot.array);

	ret = split_subtree(child, 1, 2, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &child_slot, 1,
			    NULL, 0, &prefix, &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 2U);
	KUNIT_EXPECT_PTR_EQ(test, new_tail, prefix);

	fetched = tfetch(prefix, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 1U);
	KUNIT_EXPECT_MEMEQ(test, out, new_entries, sizeof(new_entries));

	ret = lookup_step(NULL, prefix, &old_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	old_tail = lookup.node;
	memset(out, 0, sizeof(out));
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, old_entries, sizeof(old_entries));
}

static void stackdepot_trie_split_subtree_preserves_children(struct kunit *test)
{
	unsigned long child_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long desc_entries[] = { 0x4000UL };
	unsigned long new_entries[] = { 0x1000UL, 0x3000UL };
	unsigned long old_tail_lookup[] = { 0x2000UL, 0x4000UL };
	unsigned long expected[] = { 0x1000UL, 0x2000UL, 0x4000UL };
	struct stack_depot_trie_child_array_slot child_array;
	struct stack_depot_trie_child_array_slot split_array;
	struct stack_depot_trie_node_slot desc_slot;
	struct stack_depot_trie_node_slot node_slots[3];
	struct stack_depot_trie_lookup lookup;
	unsigned long out[ARRAY_SIZE(expected)] = {};
	const void *desc_head = NULL;
	const void *desc_tail = NULL;
	const void *new_tail = NULL;
	const void *old_tail;
	const void *prefix = NULL;
	unsigned int fetched;
	unsigned int used = 99;
	void *child;
	int ret;

	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), NULL, 0,
			&child);
	trie_node_slot_alloc(test, &desc_slot, desc_entries, ARRAY_SIZE(desc_entries));
	child_array.size = __stack_depot_trie_child_array_size(1);
	child_array.array = kunit_kzalloc(test, child_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, child_array.array);
	ret = append_chain(child, 3, desc_entries, ARRAY_SIZE(desc_entries),
			   &desc_slot, 1, NULL, 0, NULL, 0, &desc_head,
			   &desc_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = publish_append(NULL, child, desc_head, child_array.array,
			     child_array.size);
	KUNIT_ASSERT_EQ(test, ret, 0);

	trie_node_slot_alloc(test, &node_slots[0], child_entries, 1);
	trie_node_slot_alloc(test, &node_slots[1], &child_entries[1], 1);
	trie_node_slot_alloc(test, &node_slots[2], &new_entries[1], 1);
	split_array.size = __stack_depot_trie_child_array_size(2);
	split_array.array = kunit_kzalloc(test, split_array.size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, split_array.array);

	ret = split_subtree(child, 1, 4, new_entries, ARRAY_SIZE(new_entries),
			    node_slots, ARRAY_SIZE(node_slots), &split_array, 1,
			    NULL, 0, &prefix, &new_tail, &used);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, used, 3U);
	ret = lookup_step(NULL, prefix, old_tail_lookup,
			  ARRAY_SIZE(old_tail_lookup), &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_DESCEND);
	old_tail = lookup.node;
	ret = lookup_step(NULL, old_tail, desc_entries, ARRAY_SIZE(desc_entries),
			  &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	KUNIT_EXPECT_PTR_EQ(test, lookup.node, desc_tail);
	fetched = tfetch(desc_tail, out, ARRAY_SIZE(out));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

static void stackdepot_trie_child_array_insert_empty(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL };
	void *new_array;
	void *child;
	size_t size;
	int ret;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 1, &child);
	size = __stack_depot_trie_child_array_size(1);
	new_array = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, new_array);
	ret = child_array_insert(NULL, child, new_array, size);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_PTR_EQ(test, child_array_find(new_array, 0x1000UL), child);
}

static void stackdepot_trie_public_save_route(struct kunit *test)
{
	unsigned long hash_entries[] = { 0x401000UL, 0x402000UL };
	unsigned long trie_entries[] = { 0x501000UL, 0x502000UL, 0x503000UL };
	unsigned long get_entries[] = { 0x601000UL, 0x602000UL };
	unsigned long noalloc_entries[] = { 0x701000UL, 0x702000UL };
	unsigned long hash_flag_entries[] = { 0x901000UL, 0x902000UL };
	unsigned long fetched[ARRAY_SIZE(trie_entries)] = {};
	depot_stack_handle_t get_handle;
	depot_stack_handle_t hash_flag;
	depot_stack_handle_t hash_again;
	depot_stack_handle_t hash_handle;
	depot_stack_handle_t noalloc_handle;
	depot_stack_handle_t overlong_handle;
	depot_stack_handle_t trie_again;
	depot_stack_handle_t trie_handle;
	depot_flags_t get_flags;
	unsigned int hash_flag_nr = ARRAY_SIZE(hash_flag_entries);
	gfp_t no_spin = GFP_NOWAIT & ~__GFP_RECLAIM;
	unsigned int get_nr = ARRAY_SIZE(get_entries);
	unsigned int noalloc_nr = ARRAY_SIZE(noalloc_entries);
	unsigned int nr_entries;
	unsigned long *overlong_entries;
	unsigned int overlong_nr = CONFIG_STACKDEPOT_MAX_FRAMES + 1;
	unsigned int i;

	stackdepot_trie_add_disable_action(test);
	overlong_entries = kunit_kcalloc(test, overlong_nr, sizeof(*overlong_entries),
					 GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, overlong_entries);
	for (i = 0; i < overlong_nr; i++)
		overlong_entries[i] = 0x800000UL + i * 0x1000UL;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	hash_handle = stack_depot_save(hash_entries, ARRAY_SIZE(hash_entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, hash_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(hash_handle), 0U);
	if (!__stack_depot_trie_max_leaf_id())
		kunit_skip(test, "trie handle namespace unavailable");

	__stack_depot_trie_set_enabled(true);
	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	KUNIT_EXPECT_TRUE(test, __stack_depot_trie_ready());
	hash_again = stack_depot_save(hash_entries, ARRAY_SIZE(hash_entries), GFP_KERNEL);
	KUNIT_EXPECT_EQ(test, hash_again, hash_handle);

	trie_handle = stack_depot_save(trie_entries, ARRAY_SIZE(trie_entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, trie_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_NE(test, __stack_depot_trie_leaf_id(trie_handle), 0U);
	trie_again = stack_depot_save(trie_entries, ARRAY_SIZE(trie_entries), GFP_KERNEL);
	KUNIT_EXPECT_EQ(test, trie_again, trie_handle);
	nr_entries = stack_depot_fetch_into(trie_handle, fetched, ARRAY_SIZE(fetched));
	KUNIT_EXPECT_EQ(test, nr_entries, (unsigned int)ARRAY_SIZE(trie_entries));
	KUNIT_EXPECT_MEMEQ(test, fetched, trie_entries, sizeof(trie_entries));
	noalloc_handle = stack_depot_save_flags(noalloc_entries, noalloc_nr, no_spin, 0);
	KUNIT_ASSERT_NE(test, noalloc_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_NE(test, __stack_depot_trie_leaf_id(noalloc_handle), 0U);
	KUNIT_EXPECT_EQ(test, stack_depot_save(noalloc_entries, noalloc_nr, GFP_KERNEL),
			noalloc_handle);

	get_flags = STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_GET;
	get_handle = stack_depot_save_flags(get_entries, get_nr, GFP_KERNEL, get_flags);
	KUNIT_ASSERT_NE(test, get_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(get_handle), 0U);
	stack_depot_put(get_handle);
	get_flags = STACK_DEPOT_FLAG_CAN_ALLOC | STACK_DEPOT_FLAG_HASH;
	hash_flag = stack_depot_save_flags(hash_flag_entries, hash_flag_nr, GFP_KERNEL, get_flags);
	KUNIT_ASSERT_NE(test, hash_flag, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(hash_flag), 0U);
	overlong_handle = stack_depot_save(overlong_entries, overlong_nr, GFP_KERNEL);
	KUNIT_ASSERT_NE(test, overlong_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_EQ(test, __stack_depot_trie_leaf_id(overlong_handle), 0U);
}

#define STACKDEPOT_STRESS_THREADS 4
#define STACKDEPOT_STRESS_ITERS 64
#define STACKDEPOT_STRESS_DEPTH 8

struct stackdepot_stress_ctx {
	struct completion ready;
	struct completion done;
	struct completion *start;
	atomic_t *failures;
	unsigned int id;
};

static void stackdepot_stress_entries(unsigned int id, unsigned int iter,
				      unsigned long *entries)
{
	unsigned int i;

	for (i = 0; i < STACKDEPOT_STRESS_DEPTH; i++)
		entries[i] = 0xa0000000UL + id * 0x100000UL + iter * 0x1000UL +
			     i * 0x10UL;
}

static int stackdepot_trie_stress_worker(void *data)
{
	struct stackdepot_stress_ctx *ctx = data;
	unsigned long entries[STACKDEPOT_STRESS_DEPTH];
	unsigned long fetched[STACKDEPOT_STRESS_DEPTH];
	depot_stack_handle_t again;
	depot_stack_handle_t handle;
	unsigned int nr_entries;
	unsigned int iter;
	gfp_t no_spin;
	char buf[256];

	complete(&ctx->ready);
	wait_for_completion(ctx->start);

	for (iter = 0; iter < STACKDEPOT_STRESS_ITERS; iter++) {
		stackdepot_stress_entries(ctx->id, iter, entries);
		handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
		if (!handle || !__stack_depot_trie_leaf_id(handle)) {
			atomic_inc(ctx->failures);
			continue;
		}

		nr_entries = stack_depot_fetch_into(handle, fetched, ARRAY_SIZE(fetched));
		if (nr_entries != ARRAY_SIZE(entries) ||
		    memcmp(fetched, entries, sizeof(entries))) {
			atomic_inc(ctx->failures);
			continue;
		}

		no_spin = GFP_NOWAIT & ~__GFP_RECLAIM;
		again = stack_depot_save_flags(entries, ARRAY_SIZE(entries), no_spin, 0);
		if (again != handle)
			atomic_inc(ctx->failures);

		if (!(iter % 8) && !stack_depot_snprint(handle, buf, sizeof(buf), 0))
			atomic_inc(ctx->failures);
	}

	complete(&ctx->done);
	return 0;
}

static void stackdepot_trie_concurrent_save_fetch(struct kunit *test)
{
	struct stackdepot_stress_ctx *ctx;
	struct task_struct *task;
	atomic_t failures = ATOMIC_INIT(0);
	struct completion start;
	unsigned int created = 0;
	unsigned int i;
	size_t size;
	long timeout;
	int err = 0;

	stackdepot_trie_add_disable_action(test);
	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	if (!__stack_depot_trie_max_leaf_id())
		kunit_skip(test, "trie handle namespace unavailable");

	__stack_depot_trie_set_enabled(true);
	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);
	KUNIT_ASSERT_TRUE(test, __stack_depot_trie_ready());
	init_completion(&start);

	size = sizeof(*ctx);
	ctx = kunit_kcalloc(test, STACKDEPOT_STRESS_THREADS, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	for (i = 0; i < STACKDEPOT_STRESS_THREADS; i++) {
		init_completion(&ctx[i].ready);
		init_completion(&ctx[i].done);
		ctx[i].start = &start;
		ctx[i].failures = &failures;
		ctx[i].id = i + 1;

		task = kthread_run(stackdepot_trie_stress_worker, &ctx[i],
				   "stackdepot_stress/%u", i);
		if (IS_ERR(task)) {
			err = PTR_ERR(task);
			break;
		}
		created++;
	}

	for (i = 0; i < created; i++) {
		timeout = wait_for_completion_timeout(&ctx[i].ready,
						      msecs_to_jiffies(10000));
		KUNIT_EXPECT_GT(test, timeout, 0L);
	}
	complete_all(&start);

	for (i = 0; i < created; i++) {
		timeout = wait_for_completion_timeout(&ctx[i].done,
						      msecs_to_jiffies(10000));
		KUNIT_EXPECT_GT(test, timeout, 0L);
	}

	KUNIT_EXPECT_EQ(test, err, 0);
	KUNIT_EXPECT_EQ(test, atomic_read(&failures), 0);
}

static struct kunit_case stackdepot_test_cases[] = {
	KUNIT_CASE(stackdepot_fetch_into_roundtrip),
	KUNIT_CASE(stackdepot_fetch_into_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_count_helpers),
	KUNIT_CASE(stackdepot_trie_handle_namespace),
	KUNIT_CASE(stackdepot_trie_feature_flag),
	KUNIT_CASE(stackdepot_trie_late_init),
	KUNIT_CASE(stackdepot_trie_side_table_destroy_uninit),
	KUNIT_CASE(stackdepot_trie_side_table_alloc_store_lookup),
	KUNIT_CASE(stackdepot_trie_side_table_rejects_invalid_ids),
	KUNIT_CASE(stackdepot_trie_side_table_revoke_latest),
	KUNIT_CASE(stackdepot_trie_side_table_revoke_keeps_chunk),
	KUNIT_CASE(stackdepot_trie_side_table_restore),
	KUNIT_CASE(stackdepot_trie_side_table_chunk_boundary),
	KUNIT_CASE(stackdepot_trie_side_table_bytes),
	KUNIT_CASE(stackdepot_trie_side_prepare_updates),
	KUNIT_CASE(stackdepot_trie_side_prepare_failure),
	KUNIT_CASE(stackdepot_trie_side_prepare_duplicate_id),
	KUNIT_CASE(stackdepot_trie_side_prepare_rejects_extra_update),
	KUNIT_CASE(stackdepot_trie_side_prepare_rejects_null_leaf),
	KUNIT_CASE(stackdepot_trie_pool_alloc_size),
	KUNIT_CASE(stackdepot_trie_pool_prealloc),
	KUNIT_CASE(stackdepot_trie_alloc_prealloc),
	KUNIT_CASE(stackdepot_trie_pool_carve_current),
	KUNIT_CASE(stackdepot_trie_pool_rollback_requires_lifo),
	KUNIT_CASE(stackdepot_trie_pool_carve_current_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_pool_carve_slots),
	KUNIT_CASE(stackdepot_trie_pool_carve_slots_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_pool_carve_uses_prealloc),
	KUNIT_CASE(stackdepot_trie_pool_carve_no_prealloc_rollover),
	KUNIT_CASE(stackdepot_trie_alloc_txn_id),
	KUNIT_CASE(stackdepot_trie_alloc_txn_reserve),
	KUNIT_CASE(stackdepot_trie_alloc_txn_reserve_id_failure),
	KUNIT_CASE(stackdepot_trie_alloc_txn_commit),
	KUNIT_CASE(stackdepot_trie_alloc_txn_rollback),
	KUNIT_CASE(stackdepot_trie_alloc_workspace_plan),
	KUNIT_CASE(stackdepot_trie_alloc_workspace_insert),
	KUNIT_CASE(stackdepot_trie_save_miss),
	KUNIT_CASE(stackdepot_trie_save_miss_noalloc),
	KUNIT_CASE(stackdepot_trie_save),
	KUNIT_CASE(stackdepot_trie_save_locked),
	KUNIT_CASE(stackdepot_trie_fetch_handle_into),
	KUNIT_CASE(stackdepot_trie_snprint_public),
	KUNIT_CASE(stackdepot_trie_alloc_txn_plan),
	KUNIT_CASE(stackdepot_trie_alloc_txn_insert),
	KUNIT_CASE(stackdepot_trie_alloc_txn_insert_stale_plan),
	KUNIT_CASE(stackdepot_frame_raw_fallback),
#ifdef CONFIG_X86_64
	KUNIT_CASE(stackdepot_frame_x86_64),
#endif
#ifdef CONFIG_ARM64
	KUNIT_CASE(stackdepot_frame_arm64),
#endif
	KUNIT_CASE(stackdepot_frame_run_raw_roundtrip),
#ifdef CONFIG_ARM64
	KUNIT_CASE(stackdepot_frame_run_arm64_roundtrip),
#endif
#ifdef CONFIG_X86_64
	KUNIT_CASE(stackdepot_frame_run_x86_64_roundtrip),
	KUNIT_CASE(stackdepot_frame_run_x86_64_boundary),
	KUNIT_CASE(stackdepot_frame_run_x86_64_write_rejects_mismatch),
#endif
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_frame_run_compressed_rejects_src_scratch_overlap),
#endif
	KUNIT_CASE(stackdepot_frame_run_invalid_inputs),
	KUNIT_CASE(stackdepot_trie_node_raw_roundtrip),
	KUNIT_CASE(stackdepot_trie_node_parent_chain),
	KUNIT_CASE(stackdepot_trie_node_slice_raw),
	KUNIT_CASE(stackdepot_trie_node_slice_parent_chain),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_node_slice_compressed),
#endif
	KUNIT_CASE(stackdepot_trie_node_slice_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_node_rejects_stack_len_overflow),
	KUNIT_CASE(stackdepot_trie_node_match_raw),
	KUNIT_CASE(stackdepot_trie_append_chain_raw),
	KUNIT_CASE(stackdepot_trie_append_chain_parent),
	KUNIT_CASE(stackdepot_trie_append_chain_rejects_stack_len_overflow),
	KUNIT_CASE(stackdepot_trie_publish_append_root),
	KUNIT_CASE(stackdepot_trie_publish_append_parent),
	KUNIT_CASE(stackdepot_trie_publish_append_root_replaces_array),
	KUNIT_CASE(stackdepot_trie_publish_append_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_lookup_step_root),
	KUNIT_CASE(stackdepot_trie_lookup_step_parent_promote),
	KUNIT_CASE(stackdepot_trie_lookup_step_accepts_reparented_child),
	KUNIT_CASE(stackdepot_trie_find_leaf_root),
	KUNIT_CASE(stackdepot_trie_find_leaf_descends),
	KUNIT_CASE(stackdepot_trie_find_leaf_accepts_reparented_child),
	KUNIT_CASE(stackdepot_trie_find_leaf_misses),
	KUNIT_CASE(stackdepot_trie_find_leaf_rejects_bad_parent),
	KUNIT_CASE(stackdepot_trie_insert_append_root),
	KUNIT_CASE(stackdepot_trie_insert_append_prepare_root),
	KUNIT_CASE(stackdepot_trie_insert_append_prepare_failure),
	KUNIT_CASE(stackdepot_trie_insert_append_prepare_promote_failure),
	KUNIT_CASE(stackdepot_trie_insert_append_prepare_split),
	KUNIT_CASE(stackdepot_trie_insert_append_prepare_split_failure),
	KUNIT_CASE(stackdepot_trie_insert_append_parent),
	KUNIT_CASE(stackdepot_trie_insert_append_descends_one_level),
	KUNIT_CASE(stackdepot_trie_insert_append_descends_multiple_levels),
	KUNIT_CASE(stackdepot_trie_insert_append_descend_rejects_sibling_overlap),
	KUNIT_CASE(stackdepot_trie_insert_append_promotes_internal),
	KUNIT_CASE(stackdepot_trie_insert_append_descends_to_promote),
	KUNIT_CASE(stackdepot_trie_insert_append_promotes_with_children),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_insert_append_splits_frame_runs),
#endif
	KUNIT_CASE(stackdepot_trie_insert_append_splits_child),
	KUNIT_CASE(stackdepot_trie_insert_append_splits_prefix_leaf),
	KUNIT_CASE(stackdepot_trie_insert_plan_append),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_insert_plan_mixed_append),
#endif
	KUNIT_CASE(stackdepot_trie_insert_plan_promote),
	KUNIT_CASE(stackdepot_trie_insert_plan_promote_rejects_empty_slots),
	KUNIT_CASE(stackdepot_trie_insert_plan_split),
	KUNIT_CASE(stackdepot_trie_insert_plan_descends),
	KUNIT_CASE(stackdepot_trie_insert_plan_rejects_existing_leaf),
	KUNIT_CASE(stackdepot_trie_insert_plan_rejects_bad_child),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_existing_child),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_short_array),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_zero_frame),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_root_with_parent),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_root_slot_alias),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_parent_overlap),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_parent_cycle),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_publish_overlap),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_child_node_overlap),
	KUNIT_CASE(stackdepot_trie_insert_append_rejects_child_array_overlap),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_node_compressed_roundtrip),
	KUNIT_CASE(stackdepot_trie_node_match_compressed),
	KUNIT_CASE(stackdepot_trie_append_chain_splits_frame_runs),
	KUNIT_CASE(stackdepot_trie_append_chain_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_node_rejects_compressed_without_scratch),
#endif
	KUNIT_CASE(stackdepot_trie_node_rejects_short_storage),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_node_rejects_mixed_run),
#endif
	KUNIT_CASE(stackdepot_trie_fetch_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_child_array_init_find),
	KUNIT_CASE(stackdepot_trie_child_array_rejects_unsorted),
	KUNIT_CASE(stackdepot_trie_child_array_init_rejects_child_overlap),
	KUNIT_CASE(stackdepot_trie_child_array_insert),
	KUNIT_CASE(stackdepot_trie_child_array_insert_rejects_child_overlap),
	KUNIT_CASE(stackdepot_trie_split_child_array_init_one_child),
	KUNIT_CASE(stackdepot_trie_split_child_array_init_orders_children),
	KUNIT_CASE(stackdepot_trie_split_child_array_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_split_tail_plan_raw),
#if defined(CONFIG_ARM64) || defined(CONFIG_X86_64)
	KUNIT_CASE(stackdepot_trie_split_tail_plan_mixed_runs),
#endif
	KUNIT_CASE(stackdepot_trie_split_tail_plan_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_trie_split_precheck),
	KUNIT_CASE(stackdepot_trie_split_precheck_rejects_aliases),
	KUNIT_CASE(stackdepot_trie_split_precheck_rejects_short_array),
	KUNIT_CASE(stackdepot_trie_split_subtree_divergent_tail),
	KUNIT_CASE(stackdepot_trie_split_subtree_prefix_leaf),
	KUNIT_CASE(stackdepot_trie_split_subtree_preserves_children),
	KUNIT_CASE(stackdepot_trie_child_array_insert_empty),
	KUNIT_CASE(stackdepot_trie_public_save_route),
	KUNIT_CASE(stackdepot_trie_concurrent_save_fetch),
	{}
};

static struct kunit_suite stackdepot_test_suite = {
	.name = "stackdepot",
	.test_cases = stackdepot_test_cases,
};

kunit_test_suite(stackdepot_test_suite);

MODULE_DESCRIPTION("KUnit tests for stack depot");
MODULE_AUTHOR("Caleb Kan <ckan@cloudflare.com>");
MODULE_LICENSE("GPL");
