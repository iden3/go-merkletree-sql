package merkletree

import (
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
)

// HashElems performs a poseidon hash over the array of ElemBytes, currently we
// are using 2 elements.  Uses poseidon.Hash to be compatible with the circom
// circuits implementations.
func HashElems(elems ...*big.Int) (*Hash, error) {
	poseidonHash, err := poseidon.Hash(elems)
	if err != nil {
		return nil, err
	}
	return NewHashFromBigInt(poseidonHash)
}

// HashElemsKey performs a poseidon hash over the array of ElemBytes, currently
// we are using 2 elements.
func HashElemsKey(key *big.Int, elems ...*big.Int) (*Hash, error) {
	if key == nil {
		key = new(big.Int).SetInt64(0)
	}
	bi := make([]*big.Int, 3)
	copy(bi[:], elems)
	bi[2] = key
	poseidonHash, err := poseidon.Hash(bi)
	if err != nil {
		return nil, err
	}
	return NewHashFromBigInt(poseidonHash)
}

// setBitBigEndian sets the bit n in the bitmap to 1, in Big Endian.
func setBitBigEndian(bitmap []byte, n uint) {
	bitmap[uint(len(bitmap))-n/8-1] |= 1 << (n % 8)
}

// TestBit tests whether the bit n in bitmap is 1.
func TestBit(bitmap []byte, n uint) bool {
	return bitmap[n/8]&(1<<(n%8)) != 0
}

// testBitBigEndian tests whether the bit n in bitmap is 1, in Big Endian.
func testBitBigEndian(bitmap []byte, n uint) bool {
	return bitmap[uint(len(bitmap))-n/8-1]&(1<<(n%8)) != 0
}

// SwapEndianness swaps the order of the bytes in the slice.
func SwapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

// fillEmptySiblings fill empty siblings with HashZero
func fillEmptySiblings(siblings []*Hash, levels int) []*Hash {
	// add the rest of empty levels to the siblings
	for i := len(siblings); i < levels+1; i++ {
		siblings = append(siblings, &HashZero)
	}
	return siblings
}
