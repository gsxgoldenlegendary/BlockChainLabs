package main

import "crypto/sha256"

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

	return nil
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
