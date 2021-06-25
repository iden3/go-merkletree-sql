package merkletree

import (
	"encoding/binary"
	"fmt"
	"io"
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
	return NewHashFromBigInt(poseidonHash), nil
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
	return NewHashFromBigInt(poseidonHash), nil
}

// SetBitBigEndian sets the bit n in the bitmap to 1, in Big Endian.
func SetBitBigEndian(bitmap []byte, n uint) {
	bitmap[uint(len(bitmap))-n/8-1] |= 1 << (n % 8)
}

// TestBit tests whether the bit n in bitmap is 1.
func TestBit(bitmap []byte, n uint) bool {
	return bitmap[n/8]&(1<<(n%8)) != 0
}

// TestBitBigEndian tests whether the bit n in bitmap is 1, in Big Endian.
func TestBitBigEndian(bitmap []byte, n uint) bool {
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

func checkKVLen(kLen, vLen int) error {
	if kLen > 0xff {
		return fmt.Errorf("len(k) %d > 0xff", kLen)
	}
	if vLen > 0xffff {
		return fmt.Errorf("len(v) %d > 0xffff", vLen)
	}
	return nil
}

func serializeKV(w io.Writer, k, v []byte) error {
	if err := checkKVLen(len(k), len(v)); err != nil {
		return err
	}
	kH := byte(len(k))
	vH := Uint16ToBytes(uint16(len(v)))
	_, err := w.Write([]byte{kH})
	if err != nil {
		return err
	}
	_, err = w.Write(vH)
	if err != nil {
		return err
	}
	_, err = w.Write(k)
	if err != nil {
		return err
	}
	_, err = w.Write(v)
	if err != nil {
		return err
	}
	return nil
}

func deserializeKV(r io.Reader) ([]byte, []byte, error) {
	header := make([]byte, 3)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return nil, nil, err
	}
	kLen := int(header[0])
	vLen := int(BytesToUint16(header[1:]))
	kv := make([]byte, kLen+vLen)
	_, err = io.ReadFull(r, kv)
	if err == io.EOF {
		return nil, nil, io.ErrUnexpectedEOF
	} else if err != nil {
		return nil, nil, err
	}
	return kv[:kLen], kv[kLen:], nil
}

// Uint16ToBytes returns a byte array from a uint16
func Uint16ToBytes(u uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], u)
	return b[:]
}

// BytesToUint16 returns a uint16 from a byte array
func BytesToUint16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b[:2])
}
