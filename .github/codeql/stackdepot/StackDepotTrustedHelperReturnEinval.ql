/**
 * @name Trusted stackdepot trie helper returns direct -EINVAL
 * @description Flags direct -EINVAL returns in trusted trie structural helpers.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trusted-helper-return-einval
 */

import cpp
import StackDepot

predicate returnsEinval(ReturnStmt ret) {
  ret.hasExpr() and
  // Linux UAPI errno value for EINVAL.
  ret.getExpr().getValue().toInt() = -22
}

from ReturnStmt ret, Function f
where
  f = ret.getEnclosingFunction() and
  isTrustedStructuralHelper(f) and
  returnsEinval(ret)
select ret, "Trusted trie structural helper $@ returns direct -EINVAL here; verify this is not rediscovering a writer-side invariant.", f, f.getName()
