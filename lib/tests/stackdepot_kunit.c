// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/limits.h>
#include <linux/stackdepot.h>
#include <linux/string.h>

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

static int child_array_init(void *storage, size_t storage_size,
			    const void * const *children, unsigned int nr_children)
{
	return __stack_depot_trie_child_array_init(storage, storage_size, children,
						       nr_children);
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

	KUNIT_ASSERT_EQ(test, frame_run_init(entries, nr_entries, &run), 0);
	size = __stack_depot_trie_node_size(&run);
	KUNIT_ASSERT_GT(test, size, (size_t)0);
	*node = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, *node);
	ret = tnode_init(*node, size, parent, leaf_id, entries, nr_entries,
			 write_scratch, ARRAY_SIZE(write_scratch));
	KUNIT_ASSERT_EQ(test, ret, 0);
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
	unsigned int count;

	KUNIT_ASSERT_EQ(test, stack_depot_init(), 0);

	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(0, &count));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(0, NULL));
	__stack_depot_set_count(0, 1);
	__stack_depot_set_count(0, 0);
	__stack_depot_set_count(0, INT_MAX);
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(0, 1));
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(0, INT_MAX - 2));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(0, 1));

	handle = stack_depot_save(entries, ARRAY_SIZE(entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, handle, (depot_stack_handle_t)0);

	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(handle, INT_MAX));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(handle, 1));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(handle, &count));

	max_handle = stack_depot_save(max_entries, ARRAY_SIZE(max_entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, max_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(max_handle, INT_MAX - 1));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(max_handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX);

	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(handle, 2));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 3);

	/* Already-counted records take the refcount_add() path. */
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(handle, 4));
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
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(handle, INT_MAX));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 6);

	second_handle = stack_depot_save(zero_entries, ARRAY_SIZE(zero_entries),
					 GFP_KERNEL);
	KUNIT_ASSERT_NE(test, second_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(second_handle, 1));
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

	if (text_prefix >= SZ_4G) {
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

	for (i = 0; i < ARRAY_SIZE(node_slots); i++) {
		size_t size;

		node_slots[i].size = 128;
		size = node_slots[i].size;
		node_slots[i].node = kunit_kzalloc(test, size, GFP_KERNEL);
		KUNIT_ASSERT_NOT_NULL(test, node_slots[i].node);
	}
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

	node_slots[0].size = 128;
	node_slots[0].node = kunit_kzalloc(test, node_slots[0].size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[0].node);
	node_slots[1].size = 128;
	node_slots[1].node = kunit_kzalloc(test, node_slots[1].size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, node_slots[1].node);
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
	KUNIT_CASE(stackdepot_frame_run_invalid_inputs),
	KUNIT_CASE(stackdepot_trie_node_raw_roundtrip),
	KUNIT_CASE(stackdepot_trie_node_parent_chain),
	KUNIT_CASE(stackdepot_trie_node_match_raw),
	KUNIT_CASE(stackdepot_trie_append_chain_raw),
	KUNIT_CASE(stackdepot_trie_append_chain_parent),
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
	KUNIT_CASE(stackdepot_trie_child_array_insert),
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
