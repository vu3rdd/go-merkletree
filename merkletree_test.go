package merkletree

import (
	"math"
	"testing"
	"fmt"
)

func TestNewMerkleTree(t *testing.T) {
	chunks := [][]byte{
		[]byte{0},
		[]byte{1},
		[]byte{2},
		[]byte{3},
	}

	mTree := NewMerkleTree(chunks)
	if mTree == nil {
		t.Errorf("wanted a non-nil tree")
	}
	if mTree.Depth() != int(math.Log2(float64(len(chunks)))) {
		t.Errorf("actual depth: %d, expected depth: %.1f", mTree.Depth(), math.Log2(float64(len(chunks))))
	}
}

func TestMerkleTreeProof1(t *testing.T) {
	chunks := [][]byte{
		[]byte{0},
		[]byte{1},
		[]byte{2},
		[]byte{3},
	}

	mTree := NewMerkleTree(chunks)
	if mTree == nil {
		t.Errorf("wanted a non-nil tree")
	}
	mTree.Show()
	proof := mTree.Proof([]byte{2})
	for _, p := range proof {
		fmt.Printf("%v: %v\n", p.data, p.hash)
	}

	if !mTree.Verify(proof, []byte{2}) {
		t.Errorf("verification of the proof for the given chunk of data failed\n")
	}
}
