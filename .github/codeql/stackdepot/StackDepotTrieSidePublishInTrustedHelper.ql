/**
 * @name Trusted stackdepot trie helper publishes side-table state directly
 * @description Flags direct side-table publication calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trie-side-publish-in-trusted-helper
 */

import cpp
import StackDepot

predicate targetFunctionName(string name) {
  name = "trie_build_append_chain" or
  name = "trie_build_split" or
  name = "trie_publish_cow" or
  name = "trie_publish_first_child" or
  name = "trie_publish_split" or
  name = "trie_publish_tail_append" or
  name = "trie_promote_child"
}

predicate sidePublishFunctionName(string name) {
  name = "trie_side_publish_new" or
  name = "trie_side_publish_split"
}

predicate isTargetFunction(Function f) {
  isStackDepotFile(f.getFile()) and
  targetFunctionName(f.getName())
}

from FunctionCall call, Function f
where
  f = call.getEnclosingFunction() and
  isTargetFunction(f) and
  sidePublishFunctionName(call.getTarget().getName())
select call, "Trusted trie insertion helper $@ publishes side-table state directly; verify this belongs in the planned publish operation and has clear failure handling.", f, f.getName()
