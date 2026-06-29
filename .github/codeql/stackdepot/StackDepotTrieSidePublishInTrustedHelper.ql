/**
 * @name Trusted stackdepot trie helper publishes side-table state directly
 * @description Flags trie_side_publish() calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id scratch/stackdepot-trie-side-publish-in-trusted-helper
 */

import cpp

predicate isStackDepotFile(File f) {
  f.getRelativePath() = "lib/stackdepot.c"
}

predicate targetFunctionName(string name) {
  name = "__stack_depot_trie_insert_append_prepare" or
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
  call.getTarget().hasName("trie_side_publish")
select call, "Trusted trie insertion helper $@ publishes side-table state here; verify failure handling is not a normal path after reservation.", f, f.getName()
