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
  (
    call.getTarget().hasName("stack_depot_save") or
    call.getTarget().hasName("stack_depot_save_flags") and
    not call.getArgument(3).toString().matches("%STACK_DEPOT_FLAG_COUNTABLE%")
  )
select call, "page_owner stackdepot save should remain hash-backed COUNTABLE; avoid routing it into trie storage."
