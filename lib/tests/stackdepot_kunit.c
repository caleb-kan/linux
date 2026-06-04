// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/stackdepot.h>
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
			   unsigned int max_entries, unsigned long *scratch,
			   unsigned int nr_scratch)
{
	return __stack_depot_trie_fetch_into(leaf, entries, max_entries, scratch,
					       nr_scratch);
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
	unsigned long scratch[ARRAY_SIZE(entries)];
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned int fetched;
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 7, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(entries));
	KUNIT_EXPECT_MEMEQ(test, out, entries, sizeof(entries));
}

static void stackdepot_trie_node_parent_chain(struct kunit *test)
{
	unsigned long root_entries[] = { 0x1000UL, 0x2000UL };
	unsigned long child_entries[] = { 0x3000UL, 0x4000UL };
	unsigned long expected[] = { 0x1000UL, 0x2000UL, 0x3000UL, 0x4000UL };
	unsigned long scratch[ARRAY_SIZE(expected)];
	unsigned long out[ARRAY_SIZE(expected)] = {};
	unsigned int fetched;
	void *root;
	void *child;

	trie_node_alloc(test, root_entries, ARRAY_SIZE(root_entries), NULL, 0,
			&root);
	trie_node_alloc(test, child_entries, ARRAY_SIZE(child_entries), root, 9,
			&child);
	fetched = tfetch(child, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, (unsigned int)ARRAY_SIZE(expected));
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(expected));
}

static void stackdepot_trie_node_slice_raw(struct kunit *test)
{
	unsigned long entries[] = { 0x1000UL, 0x2000UL, 0x3000UL };
	unsigned long expected[] = { 0x2000UL, 0x3000UL };
	struct stack_depot_frame_run run;
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(slice, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(slice, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(slice, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(stack_entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(full_stack)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(stack_entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(child, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long read_scratch[ARRAY_SIZE(entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), read_scratch,
			 ARRAY_SIZE(read_scratch));
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
	unsigned long scratch[ARRAY_SIZE(old_entries)];
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
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(old_entries)];
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
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	fetched = tfetch(lookup.node, out, ARRAY_SIZE(out), scratch,
			 ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(entries)];
	unsigned long out[ARRAY_SIZE(entries)] = {};
	unsigned int fetched;
	void *node;

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 11, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long read_scratch[ARRAY_SIZE(entries)];
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
	fetched = tfetch(tail, out, ARRAY_SIZE(out), read_scratch,
			 ARRAY_SIZE(read_scratch));
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
	unsigned long scratch[ARRAY_SIZE(entries)];
	unsigned int fetched;
	void *node;
	void *root;

	memcpy(expected, out, sizeof(expected));
	trie_node_alloc(test, root_entries, ARRAY_SIZE(root_entries), NULL, 0,
			&root);
	fetched = tfetch(root, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));

	trie_node_alloc(test, entries, ARRAY_SIZE(entries), NULL, 5, &node);
	fetched = tfetch(node, out, ARRAY_SIZE(out) - 1, scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));
	fetched = tfetch(node, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch) - 1);
	KUNIT_EXPECT_EQ(test, fetched, 0);
	KUNIT_EXPECT_MEMEQ(test, out, expected, sizeof(out));
	fetched = tfetch(NULL, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(old_entries)];
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
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, 2U);
	KUNIT_EXPECT_MEMEQ(test, out, old_entries, sizeof(old_entries));
	memset(out, 0, sizeof(out));
	fetched = tfetch(new_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(old_entries)];
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

	fetched = tfetch(prefix, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
	KUNIT_EXPECT_EQ(test, fetched, 1U);
	KUNIT_EXPECT_MEMEQ(test, out, new_entries, sizeof(new_entries));

	ret = lookup_step(NULL, prefix, &old_entries[1], 1, &lookup);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, lookup.status, STACK_DEPOT_TRIE_LOOKUP_FOUND);
	old_tail = lookup.node;
	memset(out, 0, sizeof(out));
	fetched = tfetch(old_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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
	unsigned long scratch[ARRAY_SIZE(expected)];
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
	fetched = tfetch(desc_tail, out, ARRAY_SIZE(out), scratch, ARRAY_SIZE(scratch));
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

static struct kunit_case stackdepot_test_cases[] = {
	KUNIT_CASE(stackdepot_fetch_into_roundtrip),
	KUNIT_CASE(stackdepot_fetch_into_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_count_helpers),
	KUNIT_CASE(stackdepot_trie_handle_namespace),
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
