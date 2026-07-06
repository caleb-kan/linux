/**
 * @name page_owner stackdepot save must stay countable
 * @description Flags page_owner stackdepot saves that are not explicitly countable/hash-backed.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/page-owner-countable-save
 */

import cpp

predicate isPageOwnerFile(File f) {
  f.getRelativePath() = "mm/page_owner.c"
}

from FunctionCall call
where
  isPageOwnerFile(call.getFile()) and
  call.getTarget().hasName("stack_depot_save")
select call, "page_owner direct stack_depot_save() can route into trie storage; use stack_depot_save_flags() with STACK_DEPOT_FLAG_COUNTABLE."
