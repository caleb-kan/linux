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
	KUNIT_EXPECT_FALSE(test, __stack_depot_inc_count(handle, INT_MAX - 1));
	KUNIT_EXPECT_FALSE(test, __stack_depot_dec_count_and_test(handle, 1));
	KUNIT_EXPECT_FALSE(test, __stack_depot_get_count(handle, &count));

	max_handle = stack_depot_save(max_entries, ARRAY_SIZE(max_entries), GFP_KERNEL);
	KUNIT_ASSERT_NE(test, max_handle, (depot_stack_handle_t)0);
	KUNIT_EXPECT_TRUE(test, __stack_depot_inc_count(max_handle, INT_MAX - 2));
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(max_handle, &count));
	KUNIT_EXPECT_EQ(test, count, (unsigned int)INT_MAX - 1);

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
	__stack_depot_set_count(handle, 0);
	KUNIT_ASSERT_TRUE(test, __stack_depot_get_count(handle, &count));
	KUNIT_EXPECT_EQ(test, count, 2);
	__stack_depot_set_count(handle, INT_MAX);
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
#ifdef CONFIG_X86_64
	KUNIT_CASE(stackdepot_frame_run_x86_64_roundtrip),
	KUNIT_CASE(stackdepot_frame_run_x86_64_boundary),
	KUNIT_CASE(stackdepot_frame_run_x86_64_write_rejects_mismatch),
#endif
	KUNIT_CASE(stackdepot_frame_run_invalid_inputs),
	{}
};

static struct kunit_suite stackdepot_test_suite = {
	.name = "stackdepot",
	.test_cases = stackdepot_test_cases,
};

kunit_test_suite(stackdepot_test_suite);

MODULE_DESCRIPTION("KUnit tests for stack depot");
MODULE_LICENSE("GPL");
