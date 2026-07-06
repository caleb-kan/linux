/**
 * @name Stackdepot trie normal failure after publication
 * @description Flags normal error returns after side-table or structural publication starts in the writer path.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/trie-publish-then-failure
 */

import cpp
import StackDepot

predicate publishCall(FunctionCall call) {
  call.getTarget().getName().matches("trie_side_publish_%") or
  call.getTarget().getName().matches("trie_publish_%") or
  call.getTarget().hasName("trie_promote_child")
}

predicate normalFailureReturn(ReturnStmt ret) {
  ret.hasExpr() and
  (
    ret.getExpr().toString().matches("-%") or
    ret.getExpr().toString() = "ret"
  )
}

predicate retFailureGuard(IfStmt guard) {
  guard.getCondition().toString().matches("%ret%")
}

from Function f, FunctionCall pub, IfStmt guard, ReturnStmt ret
where
  isTrieWriterOrchestrator(f) and
  pub.getEnclosingFunction() = f and
  guard.getEnclosingFunction() = f and
  ret.getEnclosingFunction() = f and
  publishCall(pub) and
  retFailureGuard(guard) and
  normalFailureReturn(ret) and
  guard.getLocation().getStartLine() > pub.getLocation().getStartLine() and
  guard.getLocation().getStartLine() <= pub.getLocation().getStartLine() + 2 and
  ret.getLocation().getStartLine() >= guard.getLocation().getStartLine() and
  ret.getLocation().getStartLine() <= guard.getLocation().getEndLine()
select ret, "Normal failure guard immediately after trie side-table or structural publication; expected failures should happen before publication begins."
