/**
 * @name Trusted stackdepot trie helper revalidates trie node size
 * @description Flags __stack_depot_trie_node_size() calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id scratch/stackdepot-trie-node-size-revalidation
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

predicate isTargetFunction(Function f) {
  isStackDepotFile(f.getFile()) and
  targetFunctionName(f.getName())
}

from FunctionCall call, Function f
where
  f = call.getEnclosingFunction() and
  isTargetFunction(f) and
  call.getTarget().hasName("__stack_depot_trie_node_size")
select call, "Trusted trie insertion helper $@ revalidates trie node size here; verify this is not rechecking an invariant of trie-owned nodes.", f, f.getName()
