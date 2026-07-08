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

predicate sidePublishFunctionName(string name) {
  name = "trie_side_table_publish_new_leaf" or
  name = "trie_side_table_publish_split_leaves"
}

from FunctionCall call, Function f
where
  f = call.getEnclosingFunction() and
  isTrustedStructuralHelper(f) and
  sidePublishFunctionName(call.getTarget().getName())
select call, "Trusted trie insertion helper $@ publishes side-table state directly; verify this belongs in the planned publish operation and has clear failure handling.", f, f.getName()
