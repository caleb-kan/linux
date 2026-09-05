/**
 * @name Stackdepot trie node-size helper performs defensive checks
 * @description Flags defensive checks inside __stack_depot_trie_node_size(); constructed trie runs should make node size a direct calculation.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id stackdepot/trie-node-size-defensive-check
 * @previous-id stackdepot/trie-node-size-revalidation
 */

import cpp
import StackDepot

predicate isNodeSizeHelper(Function f) {
  isStackDepotFile(f.getFile()) and
  f.getName() = "__stack_depot_trie_node_size"
}

from Function f, IfStmt ifs
where
  isNodeSizeHelper(f) and
  ifs.getEnclosingFunction() = f
select ifs, "__stack_depot_trie_node_size() contains conditional validation; constructed frame-run metadata should make node size a direct calculation."
