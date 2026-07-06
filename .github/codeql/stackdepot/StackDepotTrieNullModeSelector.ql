/**
 * @name Stackdepot trie helper uses NULL as operation mode
 * @description Flags trusted structural helpers branching on pointer parameters, a common hidden operation selector.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/trie-null-mode-selector
 */

import cpp
import StackDepot

predicate conditionMentionsPointerParam(IfStmt ifs, Parameter p) {
  p.getType().getPointerIndirectionLevel() > 0 and
  (
    ifs.getCondition().toString().matches("%" + p.getName() + "%NULL%") or
    ifs.getCondition().toString().matches("%!" + p.getName() + "%")
  )
}

from Function f, Parameter p, IfStmt ifs
where
  isTrustedStructuralHelper(f) and
  p.getFunction() = f and
  ifs.getEnclosingFunction() = f and
  conditionMentionsPointerParam(ifs, p)
select ifs, "Trusted trie helper $@ branches on pointer parameter '$@'; verify NULL is not an operation selector.", f, f.getName(), p, p.getName()
