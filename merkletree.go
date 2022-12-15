package merkletree

import (
	"encoding/hex"
	"crypto/sha1"
	"fmt"
	//	"log"
)

const (
	L = "L"
	R = "R"
	C = "C"
)

type Hash [sha1.Size]byte
type Position string // L or R

// a particular tree, can be either a node (containing a hash and
// children nodes) or it could be just a leaf.
type MerkleTree struct {
	hash        Hash
	left        *MerkleTree
	right       *MerkleTree
	data        []byte
	depth       int
	pos         Position
}

func (h Hash) String() string {
	return hex.EncodeToString(h[:])
}

func hash(data []byte) Hash {
	return sha1.Sum(data)
}

// operations
// 1. make a merkle tree
// 2. construct a proof for a particular leaf node
// 3. verify the proof

// takes a slice of byte slices and returns a MerkleTree
// for now, assume, len(chunks) is a power of 2
func NewMerkleTree(chunks [][]byte) *MerkleTree {
	// build the tree bottom up
	if len(chunks) < 2 {
		return nil
	}

	leafs := []MerkleTree{}
	// create leafs
	for i := 0; i < len(chunks) - 1; i = i+2 {
		c0 := chunks[i]
		c1 := chunks[i+1]

		h0 := hash(c0)
		h1 := hash(c1)

		l0 := MerkleTree{
			hash: h0,
			data: c0,
			pos: L,
		}
		l1 := MerkleTree{
			hash: h1,
			data: c1,
			pos: R,
		}

		leafs = append(leafs, l0)
		leafs = append(leafs, l1)
	}

	// create other nodes, recursively, until we only have one node left in the list.
	togglePos := 0
	for {
		if len(leafs) == 1 {
			break
		}
		// consume the two nodes in the list at a time and
		// create a new Merkletree node and insert it back to
		// the list
		n0 := leafs[0]
		n1 := leafs[1]

		var position Position
		if togglePos == 0 {
			position = L
		} else {
			position = R
		}
		togglePos = (togglePos + 1) % 2
		node := MerkleTree{
			hash: hash(append(n0.hash[:], n1.hash[:] ...)),
			left: &n0,
			right: &n1,
			depth: n0.depth+1,
			pos: position,
		}

		leafs = leafs[2:]
		leafs = append(leafs, node)
	}

	leafs[0].pos = C

	return &leafs[0]
}

// given a leaf node, return a list of Nodes (nodes already contain
// their corresponding positions, which is needed to combine the
// hashes the right way)
func (mTree *MerkleTree) Proof(chunk []byte) []*MerkleTree {
	h := hash(chunk)
	// fmt.Printf("finding the proof for %s\n", h)
	node := mTree.findNode(h)
	if node == nil {
		fmt.Printf("could not find the node corresponding to the chunk\n")
		return []*MerkleTree{}
	}
	// verify that node is indeed a leaf node
	if node.left != nil || node.right != nil {
		return []*MerkleTree{}
	}

	// find the path from root to the node
	pathToNode := mTree.findPath(node, []*MerkleTree{})

	if len(pathToNode) == 0 {
		return []*MerkleTree{}
	}
	// now, for each node (starting from root), find the sibling
	// node. i.e. if the node in the path is a L node, find the R
	// node and vice versa. This list of node from bottom to top
	// is our proof.

	// assuming, the first node in our path is the root node, find
	// sibling nodes
	siblingNodes := []*MerkleTree{}
	parentNode := pathToNode[0]
	// fmt.Printf("length of the path: %d\n", len(pathToNode))
	for i := 1; i < len(pathToNode); i++ {
		n := pathToNode[i]
		if parentNode.left.hash == n.hash {
			siblingNodes = append([]*MerkleTree{parentNode.right}, siblingNodes ...)
			parentNode = n
			continue
		}
		if parentNode.right.hash == n.hash {
			siblingNodes = append([]*MerkleTree{parentNode.left}, siblingNodes ...)
			parentNode = n
			continue
		}
	}
	// fmt.Printf("%d siblings: %#+v\n", len(siblingNodes), siblingNodes)
	return siblingNodes
}

// The receiver gets the data, creates chunks and recomputes the root
// hash and let us say, it doesn't match. How do we know which block
// is corrupted?
//
// request the two hashes below the root. Check if they match, if the
// root hash doesn't match, one or both of the the hashes one level
// below the root also would not match. Let us say, the right one does
// not match. So, repeat for the two child nodes of the faulty node,
// go on until you hit the leaf to find the faulty chunk. This only
// needs O(log n) comparisons.

func (mTree *MerkleTree) Verify(proof []*MerkleTree, chunk []byte) bool {
	// combine first element of the proof with the hash of chunk
	// to obtain a hash of the parent node. Combine that with the
	// next proof element to obtain its parent... and so on. Until
	// we exhaust the proof list. At that point, the hash we have
	// should match the root hash.

	h := hash(chunk)
	var pHash Hash
	for _, p := range proof {
		if p.pos == L {
			pHash = hash(append(p.hash[:], h[:] ...))
		} else {
			pHash = hash(append(h[:], p.hash[:] ...))
		}
		h = pHash
		fmt.Printf("intermediate node hash: %s\n", pHash)
	}

	// fmt.Printf("h = %s\n, rootHash = %s\n", h, mTree.hash)
	return h == mTree.hash
}

func (mTree *MerkleTree) findNode(h Hash) *MerkleTree {
	if mTree.hash == h {
		return mTree
	}
	if mTree.left != nil {
		lN := mTree.left.findNode(h)
		if lN != nil {
			return lN
		}
	}
	if mTree.right != nil {
		rN := mTree.right.findNode(h)
		if rN != nil {
			return rN
		}
	}
	return nil
}
// return path from root to given node, if the node is in the tree.
func (mTree *MerkleTree) findPath(node *MerkleTree, path []*MerkleTree) []*MerkleTree {
	if mTree == nil {
		return []*MerkleTree{}
	}

	if mTree.hash == node.hash {
		// we found the node
		return append(path, node)
	}

	lPath := mTree.left.findPath(node, append(path, mTree))
	if len(lPath) != 0 {
		// we found a path
		return lPath
	}
	rPath := mTree.right.findPath(node, append(path, mTree))
	if len(rPath) != 0 {
		return rPath
	}

	// if both of them returned no path, then return an empty
	// slice
	return []*MerkleTree{}
}

func (mTree *MerkleTree) Depth() int {
	return mTree.depth
}

func (mTree *MerkleTree) Show() {
	if mTree == nil {
		return
	}

	// fmt.Printf("%s\n", mTree.hash)

	nodes := []*MerkleTree{}
	if mTree.left != nil {
		nodes = append(nodes, mTree.left)
	}
	if mTree.right != nil {
		nodes = append(nodes, mTree.right)
	}
	for {
		if len(nodes) == 0 {
			return
		}

		node := nodes[0]
		nodes = nodes[1:]

		// fmt.Printf("%s\n", node.hash)

		if node.left != nil {
			nodes = append(nodes, node.left)
		}
		if node.right != nil {
			nodes = append(nodes, node.right)
		}
	}
}
