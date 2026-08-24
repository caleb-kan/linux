// SPDX-License-Identifier: GPL-2.0-only

#include <linux/compiler.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/stackdepot.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_ARM64
#include <asm/memory.h>
#elif defined(CONFIG_X86_64)
#include <asm/setup.h>
#endif
#include <asm/sections.h>

#define STACKDEPOT_BENCH_MAX_STACKS	32768U
#define STACKDEPOT_BENCH_MAX_PASSES	1024U
#define STACKDEPOT_BENCH_MAX_SEED	3U
#define STACKDEPOT_BENCH_GROUP_SIZE	64U
#define STACKDEPOT_BENCH_SCENARIO_LEN	16U

#define STACKDEPOT_BENCH_FRAME_BITS	8U
#define STACKDEPOT_BENCH_OWNER_SHIFT	STACKDEPOT_BENCH_FRAME_BITS

#define STACKDEPOT_BENCH_FINGERPRINT_INIT	1469598103934665603ULL
#define STACKDEPOT_BENCH_FINGERPRINT_PRIME	1099511628211ULL

enum stackdepot_bench_scenario {
	STACKDEPOT_BENCH_INSERT_ALLOC,
	STACKDEPOT_BENCH_SAVE_HIT,
	STACKDEPOT_BENCH_FETCH,
};

static const char *
stackdepot_bench_scenario_name(enum stackdepot_bench_scenario scenario)
{
	if (scenario == STACKDEPOT_BENCH_INSERT_ALLOC)
		return "insert_alloc";
	if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		return "save_hit";
	return "fetch";
}

struct stackdepot_bench_data {
	unsigned long *entries;
	unsigned long *fetched;
	depot_stack_handle_t *handles;
	unsigned int *insert_order;
	unsigned int *replay_order;
	u64 fingerprint;
	unsigned int nr_stacks;
	unsigned int depth;
};

struct stackdepot_bench_result {
	u64 wall_ns;
	u64 cpu_ns;
	u64 operations;
	u64 corpus_fingerprint;
	unsigned int save_failures;
	unsigned int validation_errors;
	int cpu;
};

static unsigned int stackdepot_bench_depth = 32;
module_param_named(depth, stackdepot_bench_depth, uint, 0644);
MODULE_PARM_DESC(depth, "Frames in each synthetic stack");

static unsigned int stackdepot_bench_stacks = 32768;
module_param_named(stacks, stackdepot_bench_stacks, uint, 0644);
MODULE_PARM_DESC(stacks, "Distinct stacks in each corpus");

static unsigned int stackdepot_bench_passes = 32;
module_param_named(passes, stackdepot_bench_passes, uint, 0644);
MODULE_PARM_DESC(passes, "Complete corpus passes in save-hit and fetch measurements");

static unsigned int stackdepot_bench_shared_percent = 75;
module_param_named(shared_percent, stackdepot_bench_shared_percent, uint, 0644);
MODULE_PARM_DESC(shared_percent, "Percentage of frames shared by each stack group");

static unsigned int stackdepot_bench_raw_percent;
module_param_named(raw_percent, stackdepot_bench_raw_percent, uint, 0644);
MODULE_PARM_DESC(raw_percent, "Percentage of full-width frames at the end of each stack");

static unsigned int stackdepot_bench_seed = 1;
module_param_named(seed, stackdepot_bench_seed, uint, 0644);
MODULE_PARM_DESC(seed, "Synthetic stack insertion-order seed");

static char stackdepot_bench_scenario[STACKDEPOT_BENCH_SCENARIO_LEN] =
	"insert_alloc";
module_param_string(scenario, stackdepot_bench_scenario,
		    sizeof(stackdepot_bench_scenario), 0644);
MODULE_PARM_DESC(scenario, "Scenario: insert_alloc, save_hit, or fetch");

static bool stackdepot_bench_done;
static bool stackdepot_bench_run;

static u32 stackdepot_bench_token(unsigned int owner, unsigned int frame)
{
	return (owner << STACKDEPOT_BENCH_OWNER_SHIFT) | frame;
}

static unsigned long stackdepot_bench_frame(u32 token, bool raw)
{
	unsigned long offset = (unsigned long)token << 2;

	if (!raw)
		return (unsigned long)_stext + 0x100000UL + offset;

	return 0x100000UL + (offset << 1);
}

static u32 stackdepot_bench_random(u32 *state)
{
	*state = *state * 1664525U + 1013904223U;
	return *state;
}

static void stackdepot_bench_shuffle(unsigned int *order,
				     unsigned int nr_stacks, u32 state)
{
	unsigned int stack;

	for (stack = nr_stacks - 1; stack > 0; stack--) {
		unsigned int other = stackdepot_bench_random(&state) % (stack + 1);

		swap(order[stack], order[other]);
	}
}

static void stackdepot_bench_fill(struct stackdepot_bench_data *data)
{
	unsigned int shared = data->depth * stackdepot_bench_shared_percent / 100;
	unsigned int compressed = data->depth *
		(100 - stackdepot_bench_raw_percent) / 100;
	unsigned int stack, frame;
	u64 fingerprint = STACKDEPOT_BENCH_FINGERPRINT_INIT;

	for (stack = 0; stack < data->nr_stacks; stack++) {
		unsigned int group = stack / STACKDEPOT_BENCH_GROUP_SIZE;

		for (frame = 0; frame < data->depth; frame++) {
			unsigned int owner = frame < shared ? group : stack;
			u32 token = stackdepot_bench_token(owner, frame);
			bool raw = frame >= compressed;
			unsigned long entry;
			u64 corpus_token;

			entry = stackdepot_bench_frame(token, raw);
			data->entries[stack * data->depth + frame] = entry;
			corpus_token = (u64)token << 1 | raw;
			fingerprint ^= corpus_token;
			fingerprint *= STACKDEPOT_BENCH_FINGERPRINT_PRIME;
		}
		data->insert_order[stack] = stack;
		data->replay_order[stack] = stack;
	}
	stackdepot_bench_shuffle(data->insert_order, data->nr_stacks,
				 stackdepot_bench_seed + 1);
	stackdepot_bench_shuffle(data->replay_order, data->nr_stacks,
				 stackdepot_bench_seed + 0x9e3779b9U);
	for (stack = 0; stack < data->nr_stacks; stack++) {
		fingerprint ^= data->insert_order[stack];
		fingerprint *= STACKDEPOT_BENCH_FINGERPRINT_PRIME;
	}
	fingerprint ^= U32_MAX;
	fingerprint *= STACKDEPOT_BENCH_FINGERPRINT_PRIME;
	for (stack = 0; stack < data->nr_stacks; stack++) {
		fingerprint ^= data->replay_order[stack];
		fingerprint *= STACKDEPOT_BENCH_FINGERPRINT_PRIME;
	}
	data->fingerprint = fingerprint;
}

static int stackdepot_bench_alloc_data(struct stackdepot_bench_data *data)
{
	size_t order_size = sizeof(*data->insert_order);

	data->nr_stacks = stackdepot_bench_stacks;
	data->depth = stackdepot_bench_depth;
	data->entries = kvmalloc_array(data->nr_stacks,
				       data->depth * sizeof(*data->entries),
				       GFP_KERNEL);
	data->handles = kvcalloc(data->nr_stacks, sizeof(*data->handles),
				 GFP_KERNEL);
	data->fetched = kvmalloc_array(data->depth, sizeof(*data->fetched),
				       GFP_KERNEL);
	data->insert_order = kvmalloc_array(data->nr_stacks, order_size, GFP_KERNEL);
	data->replay_order = kvmalloc_array(data->nr_stacks, order_size, GFP_KERNEL);
	if (!data->entries || !data->handles || !data->fetched ||
	    !data->insert_order || !data->replay_order)
		goto err_free;

	return 0;

err_free:
	kvfree(data->replay_order);
	kvfree(data->insert_order);
	kvfree(data->fetched);
	kvfree(data->handles);
	kvfree(data->entries);
	return -ENOMEM;
}

static void stackdepot_bench_free_data(struct stackdepot_bench_data *data)
{
	kvfree(data->replay_order);
	kvfree(data->insert_order);
	kvfree(data->fetched);
	kvfree(data->handles);
	kvfree(data->entries);
}

static noinline unsigned int
stackdepot_bench_validate(struct stackdepot_bench_data *data)
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

static noinline unsigned int
stackdepot_bench_validate_hits(struct stackdepot_bench_data *data)
{
	unsigned int errors = 0;
	unsigned int stack;

	for (stack = 0; stack < data->nr_stacks; stack++) {
		unsigned long *entries = &data->entries[stack * data->depth];

		if (stack_depot_save(entries, data->depth, GFP_KERNEL) !=
		    data->handles[stack])
			errors++;
	}

	return errors;
}

static void stackdepot_bench_report(const char *scenario,
				    const struct stackdepot_bench_result *result)
{
	u64 cpu_ns_per_op = result->operations ?
		div64_u64(result->cpu_ns, result->operations) : 0;
	u64 wall_ns_per_op = result->operations ?
		div64_u64(result->wall_ns, result->operations) : 0;

	pr_info("stackdepot_bench: scenario=%s cpu=%d operations=%llu wall_ns=%llu wall_ns_per_op=%llu cpu_ns=%llu cpu_ns_per_op=%llu save_failures=%u validation_errors=%u corpus_fingerprint=%llu\n",
		scenario, result->cpu, result->operations, result->wall_ns,
		wall_ns_per_op, result->cpu_ns, cpu_ns_per_op,
		result->save_failures, result->validation_errors,
		result->corpus_fingerprint);
	cond_resched();
}

static noinline struct stackdepot_bench_result
stackdepot_bench_insert(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = data->nr_stacks,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int position;
	u64 cpu_start;
	u64 start;

	migrate_disable();
	result.cpu = smp_processor_id();
	cpu_start = task_sched_runtime(current);
	start = ktime_get_ns();
	for (position = 0; position < data->nr_stacks; position++) {
		unsigned int stack = data->insert_order[position];
		unsigned long *entries = &data->entries[stack * data->depth];
		depot_stack_handle_t handle;

		handle = stack_depot_save(entries, data->depth, GFP_KERNEL);
		data->handles[stack] = handle;
		if (!handle)
			result.save_failures++;
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	return result;
}

static noinline struct stackdepot_bench_result
stackdepot_bench_hit(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = (u64)data->nr_stacks * stackdepot_bench_passes,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int position;
	unsigned int pass;
	u64 cpu_start;
	u64 start;

	migrate_disable();
	result.cpu = smp_processor_id();
	cpu_start = task_sched_runtime(current);
	start = ktime_get_ns();
	for (pass = 0; pass < stackdepot_bench_passes; pass++) {
		for (position = 0; position < data->nr_stacks; position++) {
			unsigned int stack = data->replay_order[position];
			unsigned long *entries = &data->entries[stack * data->depth];

			stack_depot_save(entries, data->depth, GFP_KERNEL);
		}
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	return result;
}

static noinline struct stackdepot_bench_result
stackdepot_bench_fetch(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = (u64)data->nr_stacks * stackdepot_bench_passes,
		.corpus_fingerprint = data->fingerprint,
	};
	unsigned int position;
	unsigned int pass;
	u64 cpu_start;
	u64 start;

	migrate_disable();
	result.cpu = smp_processor_id();
	cpu_start = task_sched_runtime(current);
	start = ktime_get_ns();
	for (pass = 0; pass < stackdepot_bench_passes; pass++) {
		for (position = 0; position < data->nr_stacks; position++) {
			unsigned int stack = data->replay_order[position];
			depot_stack_handle_t handle = data->handles[stack];

			stack_depot_fetch_into(handle, data->fetched, data->depth);
		}
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	return result;
}

static bool stackdepot_bench_kaslr_enabled(void)
{
#ifdef CONFIG_ARM64
	return kaslr_enabled();
#else
	return kaslr_offset() != 0;
#endif
}

static int stackdepot_bench_validate_params(enum stackdepot_bench_scenario *scenario)
{
	if (!stackdepot_bench_depth ||
	    stackdepot_bench_depth > CONFIG_STACKDEPOT_MAX_FRAMES)
		return -EINVAL;
	if (!stackdepot_bench_stacks ||
	    stackdepot_bench_stacks > STACKDEPOT_BENCH_MAX_STACKS)
		return -EINVAL;
	if (!stackdepot_bench_passes ||
	    stackdepot_bench_passes > STACKDEPOT_BENCH_MAX_PASSES)
		return -EINVAL;
	if (stackdepot_bench_shared_percent >= 100 ||
	    stackdepot_bench_raw_percent > 100 ||
	    stackdepot_bench_seed > STACKDEPOT_BENCH_MAX_SEED)
		return -EINVAL;
	if (stackdepot_bench_kaslr_enabled()) {
		pr_err("stackdepot_bench: KASLR is enabled; reboot with nokaslr\n");
		return -EINVAL;
	}
	if (current->nr_cpus_allowed != 1) {
		pr_err("stackdepot_bench: invoking task must be pinned to one CPU\n");
		return -EINVAL;
	}

	if (sysfs_streq(stackdepot_bench_scenario, "insert_alloc"))
		*scenario = STACKDEPOT_BENCH_INSERT_ALLOC;
	else if (sysfs_streq(stackdepot_bench_scenario, "save_hit"))
		*scenario = STACKDEPOT_BENCH_SAVE_HIT;
	else if (sysfs_streq(stackdepot_bench_scenario, "fetch"))
		*scenario = STACKDEPOT_BENCH_FETCH;
	else
		return -EINVAL;

	return 0;
}

static int stackdepot_benchmark(void)
{
	struct stackdepot_bench_data data = {};
	struct stackdepot_bench_result prepare;
	struct stackdepot_bench_result result;
	enum stackdepot_bench_scenario scenario;
	const char *scenario_name;
	unsigned int compressed;
	unsigned int shared;
	int ret = 0;

	if (stackdepot_bench_done)
		return -EBUSY;
	ret = stackdepot_bench_validate_params(&scenario);
	if (ret)
		return ret;
	scenario_name = stackdepot_bench_scenario_name(scenario);
	ret = stackdepot_bench_alloc_data(&data);
	if (ret)
		return ret;
	stackdepot_bench_fill(&data);
	ret = stack_depot_init();
	if (ret)
		goto out_free;
	stackdepot_bench_done = true;

	shared = data.depth * stackdepot_bench_shared_percent / 100;
	compressed = data.depth * (100 - stackdepot_bench_raw_percent) / 100;
	pr_info("stackdepot_bench: begin scenario=%s depth=%u stacks=%u passes=%u shared_percent=%u shared_frames=%u raw_percent=%u raw_frames=%u group_size=%u seed=%u corpus_fingerprint=%llu\n",
		scenario_name, data.depth, data.nr_stacks,
		stackdepot_bench_passes, stackdepot_bench_shared_percent, shared,
		stackdepot_bench_raw_percent, data.depth - compressed,
		STACKDEPOT_BENCH_GROUP_SIZE, stackdepot_bench_seed,
		data.fingerprint);

	if (scenario != STACKDEPOT_BENCH_INSERT_ALLOC) {
		prepare = stackdepot_bench_insert(&data);
		prepare.validation_errors = stackdepot_bench_validate(&data);
		if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
			prepare.validation_errors += stackdepot_bench_validate_hits(&data);
		stackdepot_bench_report("prepare_insert", &prepare);
		if (prepare.save_failures || prepare.validation_errors) {
			ret = -EIO;
			goto out_report;
		}
	}

	if (scenario == STACKDEPOT_BENCH_INSERT_ALLOC)
		result = stackdepot_bench_insert(&data);
	else if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		result = stackdepot_bench_hit(&data);
	else
		result = stackdepot_bench_fetch(&data);
	if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		result.validation_errors = stackdepot_bench_validate_hits(&data);
	else
		result.validation_errors = stackdepot_bench_validate(&data);
	stackdepot_bench_report(scenario_name, &result);
	if (result.save_failures || result.validation_errors)
		ret = -EIO;

out_report:
	pr_info("stackdepot_bench: end status=%d\n", ret);
out_free:
	stackdepot_bench_free_data(&data);
	return ret;
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
	if (system_state != SYSTEM_RUNNING) {
		stackdepot_bench_run = false;
		return 0;
	}

	stackdepot_bench_run = false;
	return stackdepot_benchmark();
}

static const struct kernel_param_ops stackdepot_bench_run_ops = {
	.flags = KERNEL_PARAM_OPS_FL_NOARG,
	.set = stackdepot_bench_run_set,
};
module_param_cb(run, &stackdepot_bench_run_ops, &stackdepot_bench_run, 0200);
MODULE_PARM_DESC(run, "Run the stack depot benchmark");

MODULE_DESCRIPTION("Stack depot microbenchmark");
MODULE_LICENSE("GPL");
