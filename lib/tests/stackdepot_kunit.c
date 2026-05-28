// SPDX-License-Identifier: GPL-2.0-only

#include <kunit/test.h>
#include <linux/array_size.h>
#include <linux/gfp.h>
#include <linux/stackdepot.h>
#include <linux/string.h>

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
	depot_stack_handle_t handle;
	depot_stack_handle_t second_handle;
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
}

static struct kunit_case stackdepot_test_cases[] = {
	KUNIT_CASE(stackdepot_fetch_into_roundtrip),
	KUNIT_CASE(stackdepot_fetch_into_rejects_bad_inputs),
	KUNIT_CASE(stackdepot_count_helpers),
	{}
};

static struct kunit_suite stackdepot_test_suite = {
	.name = "stackdepot",
	.test_cases = stackdepot_test_cases,
};

kunit_test_suite(stackdepot_test_suite);

MODULE_DESCRIPTION("KUnit tests for stack depot");
MODULE_LICENSE("GPL");
