package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	s256    = secp256k1.S256()
	P, _    = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
	N, _    = new(big.Int).SetString("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
	B, _    = new(big.Int).SetString("0x0000000000000000000000000000000000000000000000000000000000000007", 0)
	Gx, _   = new(big.Int).SetString("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0)
	Gy, _   = new(big.Int).SetString("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0)
	BitSize = 256
	G       = &Point{Gx, Gy}
)

type Point struct {
	X *big.Int
	Y *big.Int
}

type Signature struct {
	s *big.Int
	r *big.Int
}

type ECC interface {
	Sign(msg []byte, secKey *big.Int) (*Signature, error)
	VerifySignature(msg []byte, signature *Signature, pubkey *Point) bool
}

type MyECC struct {
}

func NewPrivateKey() (*big.Int, error) {
	k, err := newRand()
	if err != nil {
		return nil, err
	}
	if err := checkBigIntSize(k); err != nil {
		return nil, fmt.Errorf("k error: %s", err)
	}

	return k, nil
}

func GeneratePublicKey(secKey *big.Int) *Point {
	return Multi(G, secKey)
}

func (ecc *MyECC) Sign(msg []byte, secKey *big.Int) (*Signature, error) {
	k, _ := newRand()
	R := Multi(G, k)
	r := R.X
	kInv := Inv(k, N)
	s := new(big.Int).Mod(new(big.Int).Mul(new(big.Int).Add(crypto.Keccak256Hash(msg).Big(), new(big.Int).Mul(r, secKey)), kInv), N)
	return &Signature{s, r}, nil
}

func (ecc *MyECC) VerifySignature(msg []byte, signature *Signature, pubkey *Point) bool {
	sInv := Inv(signature.s, N)
	u := new(big.Int).Mod(new(big.Int).Mul(crypto.Keccak256Hash(msg).Big(), sInv), N)
	v := new(big.Int).Mod(new(big.Int).Mul(signature.r, sInv), N)
	R := Add(Multi(G, u), Multi(pubkey, v))
	return R.X.Cmp(signature.r) == 0
}

func main() {
	seckey, err := NewPrivateKey()
	if err != nil {
		fmt.Println("error!")
	}
	pubkey := GeneratePublicKey(seckey)

	ecc := MyECC{}
	msg := []byte("test1")
	msg2 := []byte("test2")

	sign, err := ecc.Sign(msg, seckey)
	if err != nil {
		fmt.Printf("err %v\n", err)
		return
	}

	fmt.Printf("verify %v\n", ecc.VerifySignature(msg, sign, pubkey))
	fmt.Printf("verify %v\n", ecc.VerifySignature(msg2, sign, pubkey))

	fmt.Printf("libsha256 %v\n", sha256.Sum256(msg))
	fmt.Printf("mysha256 %v\n", mysha256(msg))
	fmt.Printf("libsha256 equals mysha256: %v\n", sha256.Sum256(msg) == mysha256(msg))
}

const (
	// size of the SHA256 hash in bytes
	sha256Size = 32

	// size of a SHA256 chunk in bytes
	sha256ChunkSize = 64
)

// rotate right function
func rotr(x uint32, n uint32) uint32 {
	return (x >> n) | (x << (32 - n))
}

// SHA256 hash function
func mysha256(data []byte) [sha256Size]byte {
	// initialization constants
	var H [8]uint32 = [8]uint32{
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}
	//bitlen := uint64(len(data)) * 8
	////padlen := (sha256ChunkSize - ((len(data) + 1) % sha256ChunkSize)) % sha256ChunkSize
	//var padlen int
	//if (len(data)+1)%sha256ChunkSize < 56 {
	//	padlen = 1 + sha256ChunkSize - ((len(data) + 1) % sha256ChunkSize)
	//} else {
	//	padlen = 1 + 2*sha256ChunkSize - ((len(data) + 1) % sha256ChunkSize)
	//}
	//pad := make([]byte, padlen+8)
	//pad[0] = 0x80
	//for i := 1; i < padlen; i++ {
	//	pad[i] = 0x00
	//}
	//pad[padlen+0] = byte(bitlen >> 56)
	//pad[padlen+1] = byte(bitlen >> 48)
	//pad[padlen+2] = byte(bitlen >> 40)
	//pad[padlen+3] = byte(bitlen >> 32)
	//pad[padlen+4] = byte(bitlen >> 24)
	//pad[padlen+5] = byte(bitlen >> 16)
	//pad[padlen+6] = byte(bitlen >> 8)
	//pad[padlen+7] = byte(bitlen)
	padded := append(data, 0x80)
	if len(padded)%64 < 56 {
		suffix := make([]byte, 56-(len(padded)%64))
		padded = append(padded, suffix...)
	} else {
		suffix := make([]byte, 64+56-(len(padded)%64))
		padded = append(padded, suffix...)
	}
	msgLen := len(data) * 8
	bs := make([]byte, 8)
	binary.BigEndian.PutUint64(bs, uint64(msgLen))
	padded = append(padded, bs...)

	broken := [][]byte{}

	for i := 0; i < len(padded)/64; i++ {
		broken = append(broken, padded[i*64:i*64+63])
	}
	// process chunks
	for _, chunk := range broken {
		// initialize message schedule
		w := []uint32{}

		for i := 0; i < 16; i++ {
			w = append(w, binary.BigEndian.Uint32(chunk[i*4:i*4+4]))
		}
		w = append(w, make([]uint32, 48)...)
		for j := 16; j < 64; j++ {
			s0 := rotr(w[j-15], 7) ^ rotr(w[j-15], 18) ^ (w[j-15] >> 3)
			s1 := rotr(w[j-2], 17) ^ rotr(w[j-2], 19) ^ (w[j-2] >> 10)
			w[j] = w[j-16] + s0 + w[j-7] + s1
		}

		// initialize hash value for this chunk
		var a, b, c, d, e, f, g, h uint32
		a, b, c, d, e, f, g, h = H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

		// main loop
		for j := 0; j < 64; j++ {
			S1 := rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
			ch := (e & f) ^ (^e & g)
			temp1 := h + S1 + ch + k[j] + w[j]
			S0 := rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
			maj := (a & b) ^ (a & c) ^ (b & c)
			temp2 := S0 + maj

			h, g, f, e, d, c, b, a = g, f, e, d+temp1, c, b, a, temp1+temp2
		}

		// add chunk hash to result
		H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7] = a+H[0], b+H[1], c+H[2], d+H[3], e+H[4], f+H[5], g+H[6], h+H[7]
	}

	// convert hash to byte array
	var result [sha256Size]byte
	for i := 0; i < sha256Size; i++ {
		result[i] = byte(H[i/4] >> uint((3-i%4)*8))
	}
	return result
}

// constants
var k [64]uint32 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
