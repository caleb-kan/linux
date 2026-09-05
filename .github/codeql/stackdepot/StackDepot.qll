import cpp

predicate isStackDepotFile(File f) {
  f.getRelativePath() = "lib/stackdepot.c"
}

predicate isStackDepotFunction(Function f) {
  isStackDepotFile(f.getFile())
}

predicate isTrieWriterOrchestrator(Function f) {
  isStackDepotFunction(f) and
  f.getName() = "stack_depot_trie_insert_locked"
}

predicate trustedStructuralHelperName(string name) {
  name = "trie_build_append_chain" or
  name = "trie_build_split" or
  name = "trie_child_array_insert_at" or
  name = "trie_child_array_replace_at" or
  name = "trie_node_init_slice" or
  name = "trie_publish_tail_append" or
  name = "trie_reparent_children"
}

predicate isTrustedStructuralHelper(Function f) {
  isStackDepotFunction(f) and
  trustedStructuralHelperName(f.getName())
}

predicate isSidePublishFunction(Function f) {
  isStackDepotFunction(f) and
  (f.getName() = "trie_side_table_publish_new_leaf" or
   f.getName() = "trie_side_table_publish_split_leaves")
}

predicate isBoundaryFunction(Function f) {
  isStackDepotFunction(f) and
  (
    f.getName().matches("%init%") or
    f.getName().matches("%prealloc%") or
    f.getName().matches("%lookup%") or
    f.getName().matches("%fetch%") or
    f.getName().matches("%save%") or
    f.getName().matches("%put%") or
    f.getName().matches("%print%") or
    f.getName().matches("%snprint%") or
    f.getName().matches("%handle%")
  )
}

bindingset[name]
predicate isForbiddenTrieAbstractionName(string name) {
  name.matches("%lookup_status%") or
  (name.matches("%trie_lookup%") and name.matches("%status%")) or
  name.matches("%alloc_txn%") or
  name.matches("%alloc_request%") or
  name.matches("%pool_mark%") or
  name.matches("%rollback%") or
  name.matches("%insert_plan%") or
  name.matches("%child_array_slot%") or
  name.matches("%node_slot%") or
  name.matches("%leaf_update%")
}

predicate returnsEinvalExpr(Expr e) {
  // Linux UAPI errno value for EINVAL.
  e.getValue().toInt() = -22
}
