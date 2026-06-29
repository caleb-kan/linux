/**
 * @name Trusted stackdepot trie helper returns -EINVAL
 * @description Flags normal -EINVAL returns in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id scratch/stackdepot-trusted-helper-return-einval
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

predicate returnsEinval(ReturnStmt ret) {
  ret.hasExpr() and
  ret.getExpr().getValue().toInt() = -22
}

from ReturnStmt ret, Function f
where
  f = ret.getEnclosingFunction() and
  isTargetFunction(f) and
  returnsEinval(ret)
select ret, "Trusted trie insertion helper $@ returns -EINVAL here; verify this is not rediscovering a planner/writer invariant.", f, f.getName()
