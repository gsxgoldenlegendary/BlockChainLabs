package main

import (
	"bytes"
	"crypto/sha256"
	"math"
	"math/big"
)

var (
	maxNonce = math.MaxInt64
)

const targetBits = 8

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// Run performs a proof-of-work
// implement
func (pow *ProofOfWork) Run() (int64, []byte) {
	var hashInt big.Int
	var hash [32]byte
	nonce := int64(0)

	for nonce < int64(maxNonce) {
		data := bytes.Join(
			[][]byte{
				IntToHex(pow.block.Header.Version),
				pow.block.Header.PrevBlockHash[:],
				pow.block.Header.MerkleRoot[:],
				IntToHex(pow.block.Header.Timestamp),
				IntToHex(targetBits),
				IntToHex(nonce),
			},
			[]byte{},
		)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(pow.target) == -1 {
			break
		} else {
			nonce++
		}
	}

	return nonce, hash[:]
}

// Validate validates block's PoW
// implement
func (pow *ProofOfWork) Validate() bool {
	data := bytes.Join(
		[][]byte{
			IntToHex(pow.block.Header.Version),
			pow.block.Header.PrevBlockHash[:],
			pow.block.Header.MerkleRoot[:],
			IntToHex(pow.block.Header.Timestamp),
			IntToHex(targetBits),
			IntToHex(pow.block.Header.Nonce),
		},
		[]byte{},
	)
	hash := sha256.Sum256(data)
	var hashInt big.Int
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1
}
