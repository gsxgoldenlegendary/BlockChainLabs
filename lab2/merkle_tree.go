package main

import (
	"crypto/sha256"
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
// TODO
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

// TODO
func (t *MerkleTree) SPVproof(index int) ([][]byte, error) {

	return nil, nil
}

// TODO
func (t *MerkleTree) VerifyProof(index int, path [][]byte) (bool, error) {

	return true, nil
}
