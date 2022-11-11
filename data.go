package merkletree

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// Data is the type used to represent the data stored in an entry of the MT.
// It consists of 8 elements: e0, e1, e2, e3, ...;
// where v = [e0,e1], index = [e2,e3].
type Data [DataLen]ElemBytes

func (d *Data) String() string {
	return fmt.Sprintf("%s%s%s%s", hex.EncodeToString(d[0][:]), hex.EncodeToString(d[1][:]),
		hex.EncodeToString(d[2][:]), hex.EncodeToString(d[3][:]))
}

func (d *Data) Bytes() (b [ElemBytesLen * DataLen]byte) {
	for i := 0; i < DataLen; i++ {
		copy(b[i*ElemBytesLen:(i+1)*ElemBytesLen], d[i][:])
	}
	return b
}

func (d *Data) Equal(data *Data) bool {
	return bytes.Equal(d[0][:], data[0][:]) && bytes.Equal(d[1][:], data[1][:]) &&
		bytes.Equal(d[2][:], data[2][:]) && bytes.Equal(d[3][:], data[3][:])
}

func (d *Data) MarshalText() ([]byte, error) {
	dataBytes := d.Bytes()
	return []byte(hex.EncodeToString(dataBytes[:])), nil
}

func (d *Data) UnmarshalText(text []byte) error {
	var dataBytes [ElemBytesLen * DataLen]byte
	_, err := hex.Decode(dataBytes[:], text)
	if err != nil {
		return err
	}
	*d = *NewDataFromBytes(dataBytes)
	return nil
}

func NewDataFromBytes(b [ElemBytesLen * DataLen]byte) *Data {
	d := &Data{}
	for i := 0; i < DataLen; i++ {
		copy(d[i][:], b[i*ElemBytesLen : (i+1)*ElemBytesLen][:])
	}
	return d
}
