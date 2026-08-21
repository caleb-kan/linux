// SPDX-License-Identifier: GPL-2.0-only

#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/sections.h>

#define STACKDEPOT_BENCH_MAX_STACKS	4096U
#define STACKDEPOT_BENCH_MAX_ITERATIONS	100000U
#define STACKDEPOT_BENCH_MAX_DEPTH	256U
#define STACKDEPOT_BENCH_MAX_SEED	3U
#define STACKDEPOT_BENCH_GROUP_SIZE	16U

#define STACKDEPOT_BENCH_FRAME_BITS	8U
#define STACKDEPOT_BENCH_OWNER_SHIFT	STACKDEPOT_BENCH_FRAME_BITS
#define STACKDEPOT_BENCH_CORPUS_SHIFT	20U
#define STACKDEPOT_BENCH_SEED_SHIFT	22U

#define STACKDEPOT_BENCH_FINGERPRINT_INIT	1469598103934665603ULL
#define STACKDEPOT_BENCH_FINGERPRINT_PRIME	1099511628211ULL

enum stackdepot_bench_corpus {
	STACKDEPOT_BENCH_ALLOC,
	STACKDEPOT_BENCH_NOALLOC_SPIN,
	STACKDEPOT_BENCH_NOALLOC_TRYLOCK,
};

struct stackdepot_bench_data {
	unsigned long *entries;
	unsigned long *fetched;
	depot_stack_handle_t *handles;
	u64 fingerprint;
	unsigned int nr_stacks;
	unsigned int depth;
};

struct stackdepot_bench_result {
	u64 elapsed_ns;
	u64 checksum;
	u64 operations;
	u64 corpus_fingerprint;
	unsigned int save_failures;
	unsigned int validation_errors;
	int cpu_start;
	int cpu_end;
};

static unsigned int stackdepot_bench_depth = 32;
module_param_named(depth, stackdepot_bench_depth, uint, 0644);
MODULE_PARM_DESC(depth, "Frames in each synthetic stack");

static unsigned int stackdepot_bench_stacks = 2048;
module_param_named(stacks, stackdepot_bench_stacks, uint, 0644);
MODULE_PARM_DESC(stacks, "Distinct stacks in each corpus");

static unsigned int stackdepot_bench_iterations = 20000;
module_param_named(iterations, stackdepot_bench_iterations, uint, 0644);
MODULE_PARM_DESC(iterations, "Operations in lookup-hit and fetch measurements");

static unsigned int stackdepot_bench_shared_percent = 75;
module_param_named(shared_percent, stackdepot_bench_shared_percent, uint, 0644);
MODULE_PARM_DESC(shared_percent, "Percentage of frames shared by each stack group");

static unsigned int stackdepot_bench_raw_percent;
module_param_named(raw_percent, stackdepot_bench_raw_percent, uint, 0644);
MODULE_PARM_DESC(raw_percent, "Percentage of full-width frames at the end of each stack");

static unsigned int stackdepot_bench_seed = 1;
module_param_named(seed, stackdepot_bench_seed, uint, 0644);
MODULE_PARM_DESC(seed, "Synthetic stack corpus seed");

static bool stackdepot_bench_noalloc_trylock;
module_param_named(noalloc_trylock, stackdepot_bench_noalloc_trylock, bool, 0644);
MODULE_PARM_DESC(noalloc_trylock, "Benchmark trylock instead of spin-capable no-allocation saves");

static DEFINE_MUTEX(stackdepot_bench_lock);
static bool stackdepot_bench_done;
static bool stackdepot_bench_run;

static u32 stackdepot_bench_token(unsigned int owner, unsigned int frame,
				  unsigned int seed,
				  enum stackdepot_bench_corpus corpus)
{
	return (seed << STACKDEPOT_BENCH_SEED_SHIFT) |
		(corpus << STACKDEPOT_BENCH_CORPUS_SHIFT) |
		(owner << STACKDEPOT_BENCH_OWNER_SHIFT) | frame;
}

static unsigned long stackdepot_bench_frame(u32 token, bool raw)
{
	unsigned long offset = (unsigned long)token << 2;

	if (!raw)
		return (unsigned long)_stext - 0x100000UL - offset;

	return 0x100000UL + (offset << 1);
}

static void stackdepot_bench_fill(struct stackdepot_bench_data *data,
				  enum stackdepot_bench_corpus corpus)
{
	unsigned int shared = data->depth * stackdepot_bench_shared_percent / 100;
	unsigned int compressed = data->depth *
		(100 - stackdepot_bench_raw_percent) / 100;
	unsigned int stack, frame;
	u64 fingerprint = STACKDEPOT_BENCH_FINGERPRINT_INIT;

	if (shared == data->depth)
		shared--;

	for (stack = 0; stack < data->nr_stacks; stack++) {
		unsigned int group = stack / STACKDEPOT_BENCH_GROUP_SIZE;

		for (frame = 0; frame < data->depth; frame++) {
			unsigned int owner = frame < shared ? group : stack;
			u32 token = stackdepot_bench_token(owner, frame,
						     stackdepot_bench_seed,
						     corpus);
			unsigned long entry;

			entry = stackdepot_bench_frame(token, frame >= compressed);
			data->entries[stack * data->depth + frame] = entry;
			fingerprint ^= entry;
			fingerprint *= STACKDEPOT_BENCH_FINGERPRINT_PRIME;
		}
	}
	data->fingerprint = fingerprint;
}

static int stackdepot_bench_alloc_data(struct stackdepot_bench_data *data)
{
	data->nr_stacks = stackdepot_bench_stacks;
	data->depth = stackdepot_bench_depth;
	data->entries = kvmalloc_array(data->nr_stacks,
				       data->depth * sizeof(*data->entries),
				       GFP_KERNEL);
	data->handles = kvmalloc_array(data->nr_stacks, sizeof(*data->handles),
				       GFP_KERNEL);
	data->fetched = kvmalloc_array(data->depth, sizeof(*data->fetched),
				       GFP_KERNEL);
	if (!data->entries || !data->handles || !data->fetched)
		goto err_free;

	return 0;

err_free:
	kvfree(data->fetched);
	kvfree(data->handles);
	kvfree(data->entries);
	return -ENOMEM;
}

static void stackdepot_bench_free_data(struct stackdepot_bench_data *data)
{
	kvfree(data->fetched);
	kvfree(data->handles);
	kvfree(data->entries);
}

static unsigned int stackdepot_bench_validate(struct stackdepot_bench_data *data)
{
	unsigned int errors = 0;
	unsigned int stack;

	for (stack = 0; stack < data->nr_stacks; stack++) {
		unsigned long *expected = &data->entries[stack * data->depth];
		depot_stack_handle_t handle = data->handles[stack];
		unsigned int nr_entries;

		if (!handle)
			continue;
		nr_entries = stack_depot_fetch_into(handle, data->fetched, data->depth);
		if (nr_entries != data->depth ||
		    memcmp(expected, data->fetched,
			   data->depth * sizeof(*expected)))
			errors++;
	}

	return errors;
}

static void stackdepot_bench_report(const char *scenario,
				    const struct stackdepot_bench_result *result)
{
	u64 ns_per_op = result->operations ?
		div64_u64(result->elapsed_ns, result->operations) : 0;

	pr_info("stackdepot_bench: scenario=%s cpu_start=%d cpu_end=%d operations=%llu elapsed_ns=%llu ns_per_op=%llu save_failures=%u validation_errors=%u corpus_fingerprint=%llu checksum=%llu\n",
		scenario, result->cpu_start, result->cpu_end, result->operations,
		result->elapsed_ns, ns_per_op, result->save_failures,
		result->validation_errors, result->corpus_fingerprint,
		result->checksum);
	cond_resched();
}

static struct stackdepot_bench_result
stackdepot_bench_insert(struct stackdepot_bench_data *data, gfp_t gfp_flags,
			depot_flags_t depot_flags)
{
	struct stackdepot_bench_result result = {
		.operations = data->nr_stacks,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int stack;
	u64 start;

	result.cpu_start = task_cpu(current);
	start = ktime_get_ns();
	for (stack = 0; stack < data->nr_stacks; stack++) {
		unsigned long *entries = &data->entries[stack * data->depth];
		depot_stack_handle_t handle;

		handle = stack_depot_save_flags(entries, data->depth, gfp_flags,
						depot_flags);
		data->handles[stack] = handle;
		result.checksum += handle;
		if (!handle)
			result.save_failures++;
	}
	result.elapsed_ns = ktime_get_ns() - start;
	result.cpu_end = task_cpu(current);
	result.validation_errors = stackdepot_bench_validate(data);
	return result;
}

static struct stackdepot_bench_result
stackdepot_bench_hit(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = stackdepot_bench_iterations,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int operation;
	u64 start;

	result.cpu_start = task_cpu(current);
	start = ktime_get_ns();
	for (operation = 0; operation < stackdepot_bench_iterations; operation++) {
		unsigned int stack = operation % data->nr_stacks;
		unsigned long *entries = &data->entries[stack * data->depth];
		depot_stack_handle_t handle;

		handle = stack_depot_save(entries, data->depth, GFP_KERNEL);
		result.checksum += handle;
		if (handle != data->handles[stack])
			result.validation_errors++;
	}
	result.elapsed_ns = ktime_get_ns() - start;
	result.cpu_end = task_cpu(current);
	return result;
}

static struct stackdepot_bench_result
stackdepot_bench_fetch(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = stackdepot_bench_iterations,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int operation;
	u64 start;

	result.cpu_start = task_cpu(current);
	start = ktime_get_ns();
	for (operation = 0; operation < stackdepot_bench_iterations; operation++) {
		unsigned int stack = operation % data->nr_stacks;
		depot_stack_handle_t handle = data->handles[stack];
		unsigned int nr_entries;

		nr_entries = stack_depot_fetch_into(handle, data->fetched, data->depth);
		if (nr_entries == data->depth)
			result.checksum += data->fetched[operation % data->depth];
		else
			result.validation_errors++;
	}
	result.elapsed_ns = ktime_get_ns() - start;
	result.cpu_end = task_cpu(current);
	return result;
}

static int stackdepot_bench_validate_params(void)
{
	if (!stackdepot_bench_depth ||
	    stackdepot_bench_depth > CONFIG_STACKDEPOT_MAX_FRAMES ||
	    stackdepot_bench_depth > STACKDEPOT_BENCH_MAX_DEPTH)
		return -EINVAL;
	if (!stackdepot_bench_stacks ||
	    stackdepot_bench_stacks > STACKDEPOT_BENCH_MAX_STACKS)
		return -EINVAL;
	if (!stackdepot_bench_iterations ||
	    stackdepot_bench_iterations > STACKDEPOT_BENCH_MAX_ITERATIONS)
		return -EINVAL;
	if (stackdepot_bench_shared_percent > 100 ||
	    stackdepot_bench_raw_percent > 100 ||
	    stackdepot_bench_seed > STACKDEPOT_BENCH_MAX_SEED)
		return -EINVAL;

	return 0;
}

static int stackdepot_benchmark(void)
{
	struct stackdepot_bench_data data = {};
	struct stackdepot_bench_result result;
	enum stackdepot_bench_corpus corpus;
	const char *scenario;
	gfp_t gfp_flags;
	int ret;

	if (stackdepot_bench_done)
		return -EBUSY;
	stackdepot_bench_done = true;
	ret = stackdepot_bench_validate_params();
	if (ret)
		return ret;
	ret = stack_depot_init();
	if (ret)
		return ret;
	ret = stackdepot_bench_alloc_data(&data);
	if (ret)
		return ret;

	pr_info("stackdepot_bench: begin depth=%u stacks=%u iterations=%u shared_percent=%u raw_percent=%u seed=%u noalloc_trylock=%u\n",
		stackdepot_bench_depth, stackdepot_bench_stacks,
		stackdepot_bench_iterations, stackdepot_bench_shared_percent,
		stackdepot_bench_raw_percent, stackdepot_bench_seed,
		stackdepot_bench_noalloc_trylock);

	stackdepot_bench_fill(&data, STACKDEPOT_BENCH_ALLOC);
	result = stackdepot_bench_insert(&data, GFP_KERNEL,
					 STACK_DEPOT_FLAG_CAN_ALLOC);
	stackdepot_bench_report("insert_alloc", &result);
	result = stackdepot_bench_hit(&data);
	stackdepot_bench_report("save_hit", &result);
	result = stackdepot_bench_fetch(&data);
	stackdepot_bench_report("fetch", &result);

	memset(data.handles, 0, data.nr_stacks * sizeof(*data.handles));
	if (stackdepot_bench_noalloc_trylock) {
		corpus = STACKDEPOT_BENCH_NOALLOC_TRYLOCK;
		scenario = "insert_noalloc_trylock";
		gfp_flags = GFP_NOWAIT & ~__GFP_RECLAIM;
	} else {
		corpus = STACKDEPOT_BENCH_NOALLOC_SPIN;
		scenario = "insert_noalloc_spin";
		gfp_flags = GFP_KERNEL;
	}
	stackdepot_bench_fill(&data, corpus);
	result = stackdepot_bench_insert(&data, gfp_flags, 0);
	stackdepot_bench_report(scenario, &result);

	stackdepot_bench_free_data(&data);
	pr_info("stackdepot_bench: end\n");
	return 0;
}

static int stackdepot_bench_run_set(const char *val,
				    const struct kernel_param *kp)
{
	int ret;

	if (val) {
		ret = param_set_bool(val, kp);
		if (ret)
			return ret;
	} else {
		stackdepot_bench_run = true;
	}
	if (!stackdepot_bench_run)
		return 0;
	if (system_state != SYSTEM_RUNNING)
		return 0;

	stackdepot_bench_run = false;
	mutex_lock(&stackdepot_bench_lock);
	ret = stackdepot_benchmark();
	mutex_unlock(&stackdepot_bench_lock);
	return ret;
}

static const struct kernel_param_ops stackdepot_bench_run_ops = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = stackdepot_bench_run_set,
};
module_param_cb(run, &stackdepot_bench_run_ops, &stackdepot_bench_run, 0200);
MODULE_PARM_DESC(run, "Run the stack depot benchmark");

static int __init stackdepot_bench_init(void)
{
	if (!stackdepot_bench_run)
		return 0;

	stackdepot_bench_run = false;
	return stackdepot_benchmark();
}
late_initcall(stackdepot_bench_init);

MODULE_DESCRIPTION("Stack depot microbenchmark");
MODULE_LICENSE("GPL");
