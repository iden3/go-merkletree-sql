package merkletree

import (
	"encoding/hex"

	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
)

// Entry is the generic type that is stored in the MT.  The entry should not be
// modified after creating because the cached hIndex and hValue won't be
// updated.
type Entry struct {
	Data Data
	// hIndex is a cache used to avoid recalculating hIndex
	hIndex *Hash
	// hValue is a cache used to avoid recalculating hValue
	hValue *Hash
}

type Entrier interface {
	Entry() *Entry
}

func (e *Entry) Index() []ElemBytes {
	return e.Data[:IndexLen]
}

func (e *Entry) Value() []ElemBytes {
	return e.Data[IndexLen:]
}

// HIndex calculates the hash of the Index of the Entry, used to find the path
// from the root to the leaf in the MT.
func (e *Entry) HIndex() (*Hash, error) {
	var err error
	if e.hIndex == nil { // Cache the hIndex.
		hIndex, err := HashElems(ElemBytesToBigInts(e.Index())...)
		if err != nil {
			return nil, err
		}
		e.hIndex = hIndex
	}
	return e.hIndex, err
}

// HValue calculates the hash of the Value of the Entry
func (e *Entry) HValue() (*Hash, error) {
	var err error
	if e.hValue == nil { // Cache the hValue.
		hValue, err := HashElems(ElemBytesToBigInts(e.Value())...)
		if err != nil {
			return nil, err
		}
		e.hValue = hValue
	}
	return e.hValue, err
}

// HiHv returns the HIndex and HValue of the Entry
func (e *Entry) HiHv() (*Hash, *Hash, error) {
	hi, err := e.HIndex()
	if err != nil {
		return nil, nil, err
	}
	hv, err := e.HValue()
	if err != nil {
		return nil, nil, err
	}

	return hi, hv, nil
}

func (e *Entry) Bytes() []byte {
	b := e.Data.Bytes()
	return b[:]
}

func (e1 *Entry) Equal(e2 *Entry) bool {
	return e1.Data.Equal(&e2.Data)
}

func (e Entry) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(e.Bytes())), nil
}

func (e *Entry) UnmarshalText(text []byte) error {
	return e.Data.UnmarshalText(text)
}

func (e *Entry) Clone() *Entry {
	data := NewDataFromBytes(e.Data.Bytes())
	return &Entry{Data: *data}
}

func CheckEntryInField(e Entry) bool {
	bigints := ElemBytesToBigInts(e.Data[:])
	ok := cryptoUtils.CheckBigIntArrayInField(bigints)
	return ok
}
