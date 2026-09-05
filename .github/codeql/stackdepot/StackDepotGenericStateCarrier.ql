/**
 * @name Stackdepot trie generic state carrier
 * @description Flags one-field trie wrappers and pointer/size carrier structs that may lack a real invariant.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/generic-state-carrier
 */

import cpp
import StackDepot

predicate isPointerSizeCarrier(Struct s) {
  exists(Field ptr, Field sz |
    ptr = s.getAField() and
    sz = s.getAField() and
    ptr != sz and
    ptr.getType().toString().matches("%*%") and
    (sz.getName().matches("%size%") or
     sz.getName().matches("%bytes%") or
     sz.getName().matches("%capacity%"))
  )
}

predicate isKnownTrieStateStruct(Struct s) {
  s.getName() = "stack_depot_trie_node" or
  s.getName() = "stack_depot_trie_child_array" or
  s.getName() = "stack_depot_trie_free_node" or
  s.getName() = "stack_depot_trie_free_object" or
  s.getName() = "stack_depot_trie_side_dir" or
  s.getName() = "stack_depot_trie_side_root" or
  s.getName() = "stack_depot_trie_side_prealloc" or
  s.getName() = "stack_depot_trie_alloc_workspace"
}

from Struct s
where
  isStackDepotFile(s.getFile()) and
  s.getName().matches("%trie%") and
  not isKnownTrieStateStruct(s) and
  (
    count(Field f | f = s.getAField()) = 1 or
    isPointerSizeCarrier(s)
  )
select s, "Trie struct '$@' looks like a one-field wrapper or generic pointer/size carrier; verify it carries a real invariant.", s, s.getName()
