/**
 * @name Trusted stackdepot trie helper revalidates trie node size
 * @description Flags __stack_depot_trie_node_size() calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/trie-node-size-revalidation
 */

import cpp
import StackDepot

from FunctionCall call, Function f
where
  f = call.getEnclosingFunction() and
  isTrustedTrieHelper(f) and
  call.getTarget().hasName("__stack_depot_trie_node_size")
select call, "Trusted trie insertion helper $@ recomputes trie node size here; verify this is not rechecking owned metadata or planner state.", f, f.getName()
