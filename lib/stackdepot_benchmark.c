// SPDX-License-Identifier: GPL-2.0-only

#include <linux/compiler.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/sched/cputime.h>
#include <linux/sizes.h>
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
#define STACKDEPOT_BENCH_RESCHED_INTERVAL	1024U
#define STACKDEPOT_BENCH_SCENARIO_LEN	16U
/* The benchmark protocol must not override stack_depot_max_pools. */
#define STACKDEPOT_BENCH_DEFAULT_MAX_POOLS \
	MIN((1U << DEPOT_POOL_INDEX_BITS) - 1, 8192U)

#define STACKDEPOT_BENCH_FRAME_BITS	8U
#define STACKDEPOT_BENCH_OWNER_SHIFT	STACKDEPOT_BENCH_FRAME_BITS

#define STACKDEPOT_BENCH_FINGERPRINT_INIT	1469598103934665603ULL
#define STACKDEPOT_BENCH_FINGERPRINT_PRIME	1099511628211ULL

enum stackdepot_bench_scenario {
	STACKDEPOT_BENCH_ALL,
	STACKDEPOT_BENCH_INSERT_ALLOC,
	STACKDEPOT_BENCH_SAVE_HIT,
	STACKDEPOT_BENCH_FETCH,
};

struct stackdepot_bench_config {
	enum stackdepot_bench_scenario scenario;
	unsigned int depth;
	unsigned int nr_stacks;
	unsigned int passes;
	unsigned int shared_percent;
	unsigned int raw_percent;
	unsigned int seed;
	int cpu;
	bool expect_trie;
};

static const char *
stackdepot_bench_scenario_name(enum stackdepot_bench_scenario scenario)
{
	if (scenario == STACKDEPOT_BENCH_ALL)
		return "all";
	if (scenario == STACKDEPOT_BENCH_INSERT_ALLOC)
		return "insert_alloc";
	if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		return "save_hit";
	return "fetch";
}

struct stackdepot_bench_data {
	struct stackdepot_bench_config config;
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
	bool trie_backend;
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
	"all";
module_param_string(scenario, stackdepot_bench_scenario,
		    sizeof(stackdepot_bench_scenario), 0644);
MODULE_PARM_DESC(scenario, "Scenario: all, insert_alloc, save_hit, or fetch");

static char stackdepot_bench_backend[8] = "hash";
module_param_string(backend, stackdepot_bench_backend,
		    sizeof(stackdepot_bench_backend), 0644);
MODULE_PARM_DESC(backend, "Expected backend: hash or trie");

static DEFINE_MUTEX(stackdepot_bench_lock);
static bool stackdepot_bench_done;

static u32 stackdepot_bench_token(unsigned int owner, unsigned int frame)
{
	return (owner << STACKDEPOT_BENCH_OWNER_SHIFT) | frame;
}

static unsigned long stackdepot_bench_frame(u32 token, bool raw)
{
	unsigned long offset = (unsigned long)token << 2;

	if (!raw) {
#ifdef CONFIG_ARM64
		return (unsigned long)_stext + SZ_1G + offset;
#else
		return 0xffffffff40000000UL + offset;
#endif
	}

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
	unsigned int shared = data->depth * data->config.shared_percent / 100;
	unsigned int compressed = data->depth *
		(100 - data->config.raw_percent) / 100;
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
				 data->config.seed + 1);
	stackdepot_bench_shuffle(data->replay_order, data->nr_stacks,
				 data->config.seed + 0x9e3779b9U);
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

static int
stackdepot_bench_alloc_data(struct stackdepot_bench_data *data,
			    const struct stackdepot_bench_config *config)
{
	size_t order_size = sizeof(*data->insert_order);

	data->config = *config;
	data->nr_stacks = config->nr_stacks;
	data->depth = config->depth;
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

static bool stackdepot_bench_handle_is_trie(depot_stack_handle_t handle)
{
	union handle_parts parts = { .handle = handle };

	return parts.pool_index_plus_1 > STACKDEPOT_BENCH_DEFAULT_MAX_POOLS;
}

static noinline unsigned int
stackdepot_bench_validate(struct stackdepot_bench_data *data)
{
	unsigned int errors = 0;
	unsigned int position;

	for (position = 0; position < data->nr_stacks; position++) {
		unsigned int stack = data->replay_order[position];
		unsigned long *expected = &data->entries[stack * data->depth];
		depot_stack_handle_t handle = data->handles[stack];
		unsigned int nr_entries;

		if (!handle)
			continue;
		if (stackdepot_bench_handle_is_trie(handle) !=
		    data->config.expect_trie) {
			errors++;
			continue;
		}
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
	unsigned int position;

	for (position = 0; position < data->nr_stacks; position++) {
		unsigned int stack = data->replay_order[position];
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

	pr_info("stackdepot_bench: scenario=%s cpu=%d operations=%llu wall_ns=%llu wall_ns_per_op=%llu cpu_ns=%llu cpu_ns_per_op=%llu save_failures=%u validation_errors=%u corpus_fingerprint=%llu backend=%s\n",
		scenario, result->cpu, result->operations, result->wall_ns,
		wall_ns_per_op, result->cpu_ns, cpu_ns_per_op,
		result->save_failures, result->validation_errors,
		result->corpus_fingerprint,
		result->trie_backend ? "trie" : "hash");
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
		if (position + 1 < data->nr_stacks &&
		    !((position + 1) % STACKDEPOT_BENCH_RESCHED_INTERVAL))
			cond_resched();
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	if (!result.save_failures)
		result.trie_backend = stackdepot_bench_handle_is_trie(data->handles[0]);
	return result;
}

static noinline struct stackdepot_bench_result
stackdepot_bench_hit(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = (u64)data->nr_stacks * data->config.passes,
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
	for (pass = 0; pass < data->config.passes; pass++) {
		for (position = 0; position < data->nr_stacks; position++) {
			unsigned int stack = data->replay_order[position];
			unsigned long *entries = &data->entries[stack * data->depth];
			depot_stack_handle_t handle;

			handle = stack_depot_save(entries, data->depth, GFP_KERNEL);
			result.validation_errors += handle != data->handles[stack];
		}
		if (pass + 1 < data->config.passes)
			cond_resched();
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	result.trie_backend = stackdepot_bench_handle_is_trie(data->handles[0]);
	return result;
}

static noinline struct stackdepot_bench_result
stackdepot_bench_fetch(struct stackdepot_bench_data *data)
{
	struct stackdepot_bench_result result = {
		.operations = (u64)data->nr_stacks * data->config.passes,
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
	for (pass = 0; pass < data->config.passes; pass++) {
		for (position = 0; position < data->nr_stacks; position++) {
			unsigned int stack = data->replay_order[position];
			depot_stack_handle_t handle = data->handles[stack];
			unsigned int nr_entries;

			nr_entries = stack_depot_fetch_into(handle, data->fetched, data->depth);
			result.validation_errors += nr_entries != data->depth;
		}
		if (pass + 1 < data->config.passes)
			cond_resched();
	}
	result.wall_ns = ktime_get_ns() - start;
	result.cpu_ns = task_sched_runtime(current) - cpu_start;
	migrate_enable();
	result.trie_backend = stackdepot_bench_handle_is_trie(data->handles[0]);
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

static int stackdepot_bench_validate_params(struct stackdepot_bench_config *config)
{
	config->depth = stackdepot_bench_depth;
	config->nr_stacks = stackdepot_bench_stacks;
	config->passes = stackdepot_bench_passes;
	config->shared_percent = stackdepot_bench_shared_percent;
	config->raw_percent = stackdepot_bench_raw_percent;
	config->seed = stackdepot_bench_seed;
	config->cpu = task_cpu(current);

	if (!config->depth || config->depth > CONFIG_STACKDEPOT_MAX_FRAMES)
		return -EINVAL;
	if (!config->nr_stacks || config->nr_stacks > STACKDEPOT_BENCH_MAX_STACKS)
		return -EINVAL;
	if (!config->passes || config->passes > STACKDEPOT_BENCH_MAX_PASSES)
		return -EINVAL;
	if (config->shared_percent >= 100 || config->raw_percent > 100 ||
	    config->seed > STACKDEPOT_BENCH_MAX_SEED)
		return -EINVAL;
	if (stackdepot_bench_kaslr_enabled()) {
		pr_err("stackdepot_bench: KASLR is enabled; reboot with nokaslr\n");
		return -EINVAL;
	}
	if (current->nr_cpus_allowed != 1) {
		pr_err("stackdepot_bench: invoking task must be pinned to one CPU\n");
		return -EINVAL;
	}

	if (sysfs_streq(stackdepot_bench_backend, "hash"))
		config->expect_trie = false;
	else if (sysfs_streq(stackdepot_bench_backend, "trie"))
		config->expect_trie = true;
	else
		return -EINVAL;

	if (sysfs_streq(stackdepot_bench_scenario, "all"))
		config->scenario = STACKDEPOT_BENCH_ALL;
	else if (sysfs_streq(stackdepot_bench_scenario, "insert_alloc"))
		config->scenario = STACKDEPOT_BENCH_INSERT_ALLOC;
	else if (sysfs_streq(stackdepot_bench_scenario, "save_hit"))
		config->scenario = STACKDEPOT_BENCH_SAVE_HIT;
	else if (sysfs_streq(stackdepot_bench_scenario, "fetch"))
		config->scenario = STACKDEPOT_BENCH_FETCH;
	else
		return -EINVAL;

	return 0;
}

static int
stackdepot_bench_run_scenario(struct stackdepot_bench_data *data,
			      enum stackdepot_bench_scenario scenario)
{
	struct stackdepot_bench_result result;

	if (scenario == STACKDEPOT_BENCH_INSERT_ALLOC)
		result = stackdepot_bench_insert(data);
	else if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		result = stackdepot_bench_hit(data);
	else
		result = stackdepot_bench_fetch(data);
	if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
		result.validation_errors += stackdepot_bench_validate_hits(data);
	else
		result.validation_errors += stackdepot_bench_validate(data);
	result.validation_errors += result.cpu != data->config.cpu;
	result.validation_errors += result.trie_backend != data->config.expect_trie;
	stackdepot_bench_report(stackdepot_bench_scenario_name(scenario), &result);

	return result.save_failures || result.validation_errors ? -EIO : 0;
}

static int stackdepot_benchmark(void)
{
	struct stackdepot_bench_config config;
	struct stackdepot_bench_data data = {};
	struct stackdepot_bench_result prepare;
	enum stackdepot_bench_scenario scenario;
	const char *scenario_name;
	unsigned int compressed;
	unsigned int errors;
	unsigned int shared;
	int ret = 0;

	if (stackdepot_bench_done)
		return -EBUSY;
	kernel_param_lock(THIS_MODULE);
	ret = stackdepot_bench_validate_params(&config);
	kernel_param_unlock(THIS_MODULE);
	if (ret)
		return ret;
	scenario = config.scenario;
	scenario_name = stackdepot_bench_scenario_name(scenario);
	ret = stackdepot_bench_alloc_data(&data, &config);
	if (ret)
		return ret;
	stackdepot_bench_fill(&data);
	ret = stack_depot_init();
	if (ret)
		goto out_free;
	stackdepot_bench_done = true;

	shared = data.depth * config.shared_percent / 100;
	compressed = data.depth * (100 - config.raw_percent) / 100;
	pr_info("stackdepot_bench: begin expected_backend=%s scenario=%s depth=%u stacks=%u passes=%u shared_percent=%u shared_frames=%u raw_percent=%u raw_frames=%u group_size=%u seed=%u corpus_fingerprint=%llu\n",
		config.expect_trie ? "trie" : "hash", scenario_name, data.depth,
		data.nr_stacks, config.passes, config.shared_percent, shared,
		config.raw_percent, data.depth - compressed,
		STACKDEPOT_BENCH_GROUP_SIZE, config.seed, data.fingerprint);

	if (scenario == STACKDEPOT_BENCH_ALL) {
		ret = stackdepot_bench_run_scenario(&data,
						    STACKDEPOT_BENCH_INSERT_ALLOC);
		if (ret)
			goto out_report;
		errors = stackdepot_bench_validate_hits(&data);
		if (errors) {
			pr_err("stackdepot_bench: phase=save_hit_warmup validation_errors=%u\n",
			       errors);
			ret = -EIO;
			goto out_report;
		}
		ret = stackdepot_bench_run_scenario(&data,
						    STACKDEPOT_BENCH_SAVE_HIT);
		if (ret)
			goto out_report;
		errors = stackdepot_bench_validate(&data);
		if (errors) {
			pr_err("stackdepot_bench: phase=fetch_warmup validation_errors=%u\n",
			       errors);
			ret = -EIO;
			goto out_report;
		}
		ret = stackdepot_bench_run_scenario(&data, STACKDEPOT_BENCH_FETCH);
		goto out_report;
	}

	if (scenario != STACKDEPOT_BENCH_INSERT_ALLOC) {
		prepare = stackdepot_bench_insert(&data);
		prepare.validation_errors = stackdepot_bench_validate(&data);
		stackdepot_bench_report("prepare_insert", &prepare);
		if (prepare.save_failures || prepare.validation_errors) {
			ret = -EIO;
			goto out_report;
		}
		if (scenario == STACKDEPOT_BENCH_SAVE_HIT)
			errors = stackdepot_bench_validate_hits(&data);
		else
			errors = stackdepot_bench_validate(&data);
		if (errors) {
			pr_err("stackdepot_bench: phase=%s_warmup validation_errors=%u\n",
			       scenario_name, errors);
			ret = -EIO;
			goto out_report;
		}
	}

	ret = stackdepot_bench_run_scenario(&data, scenario);

out_report:
	pr_info("stackdepot_bench: end status=%d\n", ret);
out_free:
	stackdepot_bench_free_data(&data);
	return ret;
}

static ssize_t stackdepot_bench_run_write(struct file *file,
					  const char __user *buf,
					  size_t count, loff_t *ppos)
{
	int ret;

	if (!count)
		return -EINVAL;
	mutex_lock(&stackdepot_bench_lock);
	ret = stackdepot_benchmark();
	mutex_unlock(&stackdepot_bench_lock);
	return ret ? ret : count;
}

static const struct file_operations stackdepot_bench_run_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = stackdepot_bench_run_write,
	.llseek = noop_llseek,
};

static int __init stackdepot_bench_init(void)
{
	struct dentry *dir;

	dir = debugfs_create_dir("stackdepot_benchmark", NULL);
	debugfs_create_file("run", 0200, dir, NULL, &stackdepot_bench_run_fops);
	return 0;
}
late_initcall(stackdepot_bench_init);

MODULE_DESCRIPTION("Stack depot microbenchmark");
MODULE_LICENSE("GPL");
