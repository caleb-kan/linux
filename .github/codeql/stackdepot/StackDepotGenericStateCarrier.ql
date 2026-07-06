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
    ptr.getType().getPointerIndirectionLevel() > 0 and
    (sz.getName().matches("%size%") or
     sz.getName().matches("%bytes%") or
     sz.getName().matches("%capacity%"))
  )
}

from Struct s
where
  isStackDepotFile(s.getFile()) and
  s.getName().matches("%trie%") and
  (
    count(Field f | f = s.getAField()) = 1 or
    isPointerSizeCarrier(s)
  )
select s, "Trie struct '$@' looks like a one-field wrapper or generic pointer/size carrier; verify it carries a real invariant.", s, s.getName()
