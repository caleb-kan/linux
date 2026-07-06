/**
 * @name Trusted stackdepot trie helper rediscovers insertion state
 * @description Flags calls that rediscover planner/writer state inside trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trie-state-rediscovery
 */

import cpp
import StackDepot

predicate rediscoveryFunctionName(string name) {
  name = "trie_child_array_find_slot" or
  name = "trie_child_array_can_append" or
  name = "stack_depot_trie_lookup"
}

from FunctionCall call, Function f, Function target
where
  f = call.getEnclosingFunction() and
  isTrustedStructuralHelper(f) and
  target = call.getTarget() and
  rediscoveryFunctionName(target.getName())
select call, "Trusted trie insertion helper $@ calls $@ here; verify this state was not already established by planning/writer serialization.", f, f.getName(), target, target.getName()
