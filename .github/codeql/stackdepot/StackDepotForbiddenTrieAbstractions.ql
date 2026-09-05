/**
 * @name Deleted stackdepot trie abstraction reintroduced
 * @description Flags names matching deleted lookup/status/transaction/slot/rollback machinery.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/forbidden-trie-abstraction
 */

import cpp
import StackDepot

from Declaration d
where
  isStackDepotFile(d.getFile()) and
  isForbiddenTrieAbstractionName(d.getName())
select d, "Stackdepot trie declaration '$@' looks like deleted status, transaction, plan, slot, update, or rollback machinery.", d, d.getName()
