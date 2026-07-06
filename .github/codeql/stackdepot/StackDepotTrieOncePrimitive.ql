/**
 * @name Stackdepot trie READ_ONCE or WRITE_ONCE use
 * @description Flags trie-specific READ_ONCE/WRITE_ONCE uses so reviewers verify a lockless reader or publication pairing.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id stackdepot/trie-once-primitive
 */

import cpp
import StackDepot

from MacroInvocation m
where
  isStackDepotFile(m.getFile()) and
  (m.getMacroName() = "READ_ONCE" or m.getMacroName() = "WRITE_ONCE") and
  (
    m.toString().matches("%nr_children%") or
    m.toString().matches("%trie%")
  )
select m, "Trie-specific $@ use; verify a documented lockless reader or publication pairing justifies it.", m, m.getMacroName()
