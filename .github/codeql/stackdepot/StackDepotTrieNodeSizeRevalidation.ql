/**
 * @name Trusted stackdepot trie helper revalidates trie node size
 * @description Flags __stack_depot_trie_node_size() calls in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trie-node-size-revalidation
 */

import cpp
import StackDepot

predicate usesTrieOwnedRun(FunctionCall call) {
  call.getArgument(0).toString().matches("%->run%")
}

from FunctionCall call, Function f
where
  f = call.getEnclosingFunction() and
  isTrustedTrieHelper(f) and
  call.getTarget().hasName("__stack_depot_trie_node_size") and
  usesTrieOwnedRun(call)
select call, "Trusted trie insertion helper $@ revalidates trie node size here; verify this is not rechecking an invariant of trie-owned nodes.", f, f.getName()
