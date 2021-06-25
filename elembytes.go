package merkletree

import (
	"encoding/hex"
	"fmt"
	"math/big"
)

const (
	// ElemBytesLen is the length of the Hash byte array
	ElemBytesLen = 32
)

// ElemBytes is the basic type used to store data in the MT.  ElemBytes
// corresponds to the serialization of an element from mimc7.
type ElemBytes [ElemBytesLen]byte

func NewElemBytesFromBigInt(v *big.Int) (e ElemBytes) {
	bs := SwapEndianness(v.Bytes())
	copy(e[:], bs)
	return e
}

func (e *ElemBytes) BigInt() *big.Int {
	return new(big.Int).SetBytes(SwapEndianness(e[:]))
}

// String returns the first 4 bytes of ElemBytes in hex.
func (e *ElemBytes) String() string {
	return fmt.Sprintf("%v...", hex.EncodeToString(e[:4]))
}

// ElemBytesToBytes serializes an array of ElemBytes to []byte.
func ElemBytesToBytes(es []ElemBytes) []byte {
	bs := make([]byte, len(es)*ElemBytesLen)
	for i := 0; i < len(es); i++ {
		copy(bs[i*ElemBytesLen:(i+1)*ElemBytesLen], es[i][:])
	}
	return bs
}

// ElemBytesToBigInts serializes an array of ElemBytes to []byte.
func ElemBytesToBigInts(es []ElemBytes) []*big.Int {
	bs := make([]*big.Int, len(es))
	for i := 0; i < len(es); i++ {
		bs[i] = es[i].BigInt()
	}
	return bs
}
