/**
 * @name Trusted stackdepot trie helper rediscovers insertion state
 * @description Flags calls that rediscover planner/writer state inside trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id scratch/stackdepot-trie-state-rediscovery
 */

import cpp

predicate isStackDepotFile(File f) {
  f.getRelativePath() = "lib/stackdepot.c"
}

predicate targetFunctionName(string name) {
  name = "__stack_depot_trie_insert_append_prepare" or
  name = "__stack_depot_trie_append_chain" or
  name = "__stack_depot_trie_child_array_insert" or
  name = "__stack_depot_trie_node_init_slice" or
  name = "trie_clone_promoted_node" or
  name = "trie_publish_append_prepare" or
  name = "trie_promote_child" or
  name = "trie_split_subtree_prepare" or
  name = "trie_split_child"
}

predicate rediscoveryFunctionName(string name) {
  name = "stack_depot_trie_child_lower_bound" or
  name = "trie_child_array_can_append" or
  name = "__stack_depot_trie_lookup_step"
}

predicate isTargetFunction(Function f) {
  isStackDepotFile(f.getFile()) and
  targetFunctionName(f.getName())
}

from FunctionCall call, Function f, Function target
where
  f = call.getEnclosingFunction() and
  isTargetFunction(f) and
  target = call.getTarget() and
  rediscoveryFunctionName(target.getName())
select call, "Trusted trie insertion helper $@ calls $@ here; verify this state was not already established by planning/writer serialization.", f, f.getName(), target, target.getName()
