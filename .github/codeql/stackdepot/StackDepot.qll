import cpp

predicate isStackDepotFile(File f) {
  f.getRelativePath() = "lib/stackdepot.c"
}

predicate trustedTrieHelperName(string name) {
  name = "__stack_depot_trie_insert_append_prepare" or
  name = "__stack_depot_trie_append_chain" or
  name = "__stack_depot_trie_child_array_insert" or
  name = "__stack_depot_trie_node_init_slice" or
  name = "trie_clone_promoted_node" or
  name = "trie_publish_append_prepare" or
  name = "trie_promote_child" or
  name = "trie_split_subtree_prepare" or
  name = "trie_split_child"
}

predicate isTrustedTrieHelper(Function f) {
  isStackDepotFile(f.getFile()) and
  trustedTrieHelperName(f.getName())
}
