/**
 * @name Trusted stackdepot trie helper publishes side-table state directly
 * @description Flags trie_side_publish() calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trie-side-publish-in-trusted-helper
 */

import cpp
import StackDepot

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
select call, "Trusted trie insertion helper $@ publishes side-table state directly; verify this belongs in the planned publish operation and has clear failure handling.", f, f.getName()
