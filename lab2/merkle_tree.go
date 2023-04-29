package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
)

// MerkleTree represent a Merkle tree
type MerkleTree struct {
	RootNode *MerkleNode
	Leaf     [][]byte
}

// MerkleNode represent a Merkle tree node
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleTree creates a new Merkle tree from a sequence of data
func NewMerkleTree(data [][]byte) *MerkleTree {
	if len(data)%2 == 1 {
		data = append(data, data[len(data)-1])
	}
	var nodes []*MerkleNode
	for _, datum := range data {
		node := NewMerkleNode(nil, nil, datum)
		nodes = append(nodes, node)
	}
	length := len(nodes)
	index := 0
	for length > 1 {
		var level []*MerkleNode
		for index = 0; index < length; index += 2 {
			if index+1 == length {
				level = append(level, NewMerkleNode(nodes[index], nodes[index], nil))
				break
			}
			level = append(level, NewMerkleNode(nodes[index], nodes[index+1], nil))
		}
		nodes = level
		length = int(math.Ceil(float64(length) / 2))
	}
	return &MerkleTree{nodes[0], data}
}

// NewMerkleNode creates a new Merkle tree node
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	var hash [32]byte
	node := new(MerkleNode)
	node.Right = right
	node.Left = left
	if data == nil {
		hash = sha256.Sum256(append(left.Data, right.Data...))
	} else {
		hash = sha256.Sum256(data)
	}
	node.Data = hash[:]
	return node
}

// SPVproof returns the sparse Merkle proof for a given leaf node at the specified index.
func (t *MerkleTree) SPVproof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.Leaf) {
		return nil, fmt.Errorf("invalid index: %d", index)
	}

	proof := make([][]byte, 0)
	currentNode := t.RootNode
	level := 1 << (int(math.Log2(float64(len(t.Leaf)))) - 1)
	// Traverse the tree from the root to the leaf node, keeping track of the sibling nodes
	for currentNode.Left != nil && currentNode.Right != nil {
		if index/level == 0 {
			proof = append(proof, currentNode.Right.Data)
			currentNode = currentNode.Left
		} else {
			proof = append(proof, currentNode.Left.Data)
			currentNode = currentNode.Right
		}
		level = level >> 1
	}
	return proof, nil
}

func (t *MerkleTree) VerifyProof(index int, path [][]byte) (bool, error) {

	if index < 0 || index >= len(t.Leaf) {
		return false, fmt.Errorf("invalid index: %d", index)
	}
	var hash [32]byte
	leaf := sha256.Sum256(t.Leaf[index])
	if index%2 == 0 {
		hash = sha256.Sum256(append(leaf[:], path[len(path)-1]...))
	} else {
		hash = sha256.Sum256(append(path[len(path)-1], leaf[:]...))
	}
	index = index / 2
	for i := len(path) - 2; i >= 0; i-- {
		if index%2 == 0 {
			hash = sha256.Sum256(append(hash[:], path[i]...))
		} else {
			hash = sha256.Sum256(append(path[i], hash[:]...))
		}
		index = index / 2
	}
	if bytes.Equal(hash[:], t.RootNode.Data) {
		return true, nil
	} else {
		return false, nil
	}
}
