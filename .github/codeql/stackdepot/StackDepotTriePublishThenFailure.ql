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
    ret.getExpr().getValue().toInt() < 0 or
    ret.getExpr().toString() = "ret"
  )
}

from Function f, FunctionCall pub, ReturnStmt ret
where
  isTrieWriterOrchestrator(f) and
  pub.getEnclosingFunction() = f and
  ret.getEnclosingFunction() = f and
  publishCall(pub) and
  normalFailureReturn(ret) and
  pub.getLocation().getStartLine() < ret.getLocation().getStartLine()
select ret, "Normal failure return after trie side-table or structural publication; expected failures should happen before publication begins."
