/**
 * @name Trusted stackdepot trie helper returns direct -EINVAL
 * @description Flags direct -EINVAL returns in trusted trie insertion helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trusted-helper-return-einval
 */

import cpp
import StackDepot

predicate returnsEinval(ReturnStmt ret) {
  ret.hasExpr() and
  ret.getExpr().getValue().toInt() = -22
}

from ReturnStmt ret, Function f
where
  f = ret.getEnclosingFunction() and
  isTrustedTrieHelper(f) and
  returnsEinval(ret)
select ret, "Trusted trie insertion helper $@ returns direct -EINVAL here; verify this is not rediscovering a planner/writer invariant.", f, f.getName()
