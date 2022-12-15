# Introduction

Merkle Tree implementation in Go. Written mainly to learn about merkle
trees and not for production use. The hashing scheme is fixed (sha1).

# API

- Create a merkle tree:

```
NewMerkletree([]byte) -> *MerkleTree
```

- Create proof that a chunk exists in the tree. Given a chunk of data,
  produces the list of sibling nodes.

```
MerkleTree.Proof([]byte) -> []*MerkleTree
```

- Verify that a chunk exists in the tree, given the proof.

```
MerkleTree.Verify(proof []*MerkleTree, chunk []byte) -> bool
```
