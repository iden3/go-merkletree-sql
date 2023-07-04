package merkletree

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
)

// Proof defines the required elements for a MT proof of existence or
// non-existence.
type Proof struct {
	// existence indicates whether this is a proof of existence or
	// non-existence
	Existence bool
	// depth indicates how deep in the tree the proof goes
	depth uint
	// notempties is a bitmap of non-empty siblings found in siblings
	notempties [ElemBytesLen - proofFlagsLen]byte
	// siblings is a list of non-empty sibling keys
	siblings []*Hash
	// Auxiliary node if needed
	NodeAux *NodeAux
}

// proofJSON defines the required elements for a MT proof in json serializable structure
type proofJSON struct {
	// existence indicates whether this is a proof of existence or
	// non-existence
	Existence bool `json:"existence"`
	// Siblings is a list of all sibling keys
	Siblings []*Hash `json:"siblings"`
	// Auxiliary node if needed
	NodeAux *NodeAux `json:"node_aux,omitempty"`
}

// NewProofFromBytes parses a byte array into a Proof
func NewProofFromBytes(bs []byte) (*Proof, error) {
	if len(bs) < ElemBytesLen {
		return nil, ErrInvalidProofBytes
	}
	p := &Proof{}
	if (bs[0] & 0x01) == 0 {
		p.Existence = true
	}
	p.depth = uint(bs[1])
	copy(p.notempties[:], bs[proofFlagsLen:ElemBytesLen])
	siblingBytes := bs[ElemBytesLen:]
	sibIdx := 0
	for i := uint(0); i < p.depth; i++ {
		if TestBitBigEndian(p.notempties[:], i) {
			if len(siblingBytes) < (sibIdx+1)*ElemBytesLen {
				return nil, ErrInvalidProofBytes
			}
			var sib Hash
			copy(sib[:],
				siblingBytes[sibIdx*ElemBytesLen:(sibIdx+1)*ElemBytesLen])
			p.siblings = append(p.siblings, &sib)
			sibIdx++
		}
	}

	if !p.Existence && ((bs[0] & 0x02) != 0) {
		p.NodeAux = &NodeAux{Key: &Hash{}, Value: &Hash{}}
		nodeAuxBytes := siblingBytes[len(p.siblings)*ElemBytesLen:]
		if len(nodeAuxBytes) != 2*ElemBytesLen {
			return nil, ErrInvalidProofBytes
		}
		copy(p.NodeAux.Key[:], nodeAuxBytes[:ElemBytesLen])
		copy(p.NodeAux.Value[:], nodeAuxBytes[ElemBytesLen:2*ElemBytesLen])
	}
	return p, nil
}

// NewProofFromData reconstructs proof from siblings and auxiliary node
func NewProofFromData(existence bool,
	allSiblings []*Hash,
	nodeAux *NodeAux) (*Proof, error) {
	var p Proof
	p.Existence = existence
	p.NodeAux = nodeAux
	var siblings []*Hash
	p.depth = 0
	for lvl, sibling := range allSiblings {
		if !sibling.Equals(&HashZero) {
			SetBitBigEndian(p.notempties[:], uint(lvl))
			siblings = append(siblings, sibling)
			p.depth = uint(lvl) + 1
		}
	}
	p.siblings = siblings
	return &p, nil
}

// Bytes serializes a Proof into a byte array.
func (p *Proof) Bytes() []byte {
	bsLen := proofFlagsLen + len(p.notempties) + ElemBytesLen*len(p.siblings)
	if p.NodeAux != nil {
		bsLen += 2 * ElemBytesLen
	}
	bs := make([]byte, bsLen)

	if !p.Existence {
		bs[0] |= 0x01
	}
	bs[1] = byte(p.depth)
	copy(bs[proofFlagsLen:len(p.notempties)+proofFlagsLen], p.notempties[:])
	siblingsBytes := bs[len(p.notempties)+proofFlagsLen:]
	for i, k := range p.siblings {
		copy(siblingsBytes[i*ElemBytesLen:(i+1)*ElemBytesLen], k[:])
	}
	if p.NodeAux != nil {
		bs[0] |= 0x02
		copy(bs[len(bs)-2*ElemBytesLen:], p.NodeAux.Key[:])
		copy(bs[len(bs)-1*ElemBytesLen:], p.NodeAux.Value[:])
	}
	return bs
}

// AllSiblings returns all the siblings of the proof.
func (p *Proof) AllSiblings() []*Hash {
	return SiblingsFromProof(p)
}

// MarshalJSON implements json.Marshaler interface
func (p Proof) MarshalJSON() ([]byte, error) {
	obj := proofJSON{
		Existence: p.Existence,
		Siblings:  p.AllSiblings(),
		NodeAux:   p.NodeAux,
	}
	return json.Marshal(obj)
}

// UnmarshalJSON implements json.Unmarshaler interface
func (p *Proof) UnmarshalJSON(data []byte) error {
	var obj proofJSON
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return err
	}

	proof, err := NewProofFromData(obj.Existence, obj.Siblings, obj.NodeAux)
	if err != nil {
		return err
	}

	p.siblings = proof.siblings
	p.Existence = proof.Existence
	p.NodeAux = proof.NodeAux
	p.notempties = proof.notempties
	p.depth = proof.depth

	return nil
}

// SiblingsFromProof returns all the siblings of the proof.
func SiblingsFromProof(proof *Proof) []*Hash {
	sibIdx := 0
	siblings := []*Hash{}
	for lvl := 0; lvl < int(proof.depth); lvl++ {
		if TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblings = append(siblings, proof.siblings[sibIdx])
			sibIdx++
		} else {
			siblings = append(siblings, &HashZero)
		}
	}
	return siblings
}

// VerifyProof verifies the Merkle Proof for the entry and root.
func VerifyProof(rootKey *Hash, proof *Proof, k, v *big.Int) bool {
	rootFromProof, err := RootFromProof(proof, k, v)
	if err != nil {
		return false
	}
	return bytes.Equal(rootKey[:], rootFromProof[:])
}

// RootFromProof calculates the root that would correspond to a tree whose
// siblings are the ones in the proof with the leaf hashing to hIndex and
// hValue.
func RootFromProof(proof *Proof, k, v *big.Int) (*Hash, error) {
	kHash, err := NewHashFromBigInt(k)
	if err != nil {
		return nil, fmt.Errorf("can't create hash from Key: %w", err)
	}
	vHash, err := NewHashFromBigInt(v)
	if err != nil {
		return nil, fmt.Errorf("can't create hash from Value: %w", err)
	}
	sibIdx := len(proof.siblings) - 1
	var midKey *Hash
	if proof.Existence {
		midKey, err = LeafKey(kHash, vHash)
		if err != nil {
			return nil, err
		}
	} else {
		if proof.NodeAux == nil {
			midKey = &HashZero
		} else {
			if bytes.Equal(kHash[:], proof.NodeAux.Key[:]) {
				return nil,
					fmt.Errorf("Non-existence proof being checked against hIndex equal to nodeAux")
			}
			midKey, err = LeafKey(proof.NodeAux.Key, proof.NodeAux.Value)
			if err != nil {
				return nil, err
			}
		}
	}
	path := getPath(int(proof.depth), kHash[:])
	var siblingKey *Hash
	for lvl := int(proof.depth) - 1; lvl >= 0; lvl-- {
		if TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblingKey = proof.siblings[sibIdx]
			sibIdx--
		} else {
			siblingKey = &HashZero
		}
		if path[lvl] {
			midKey, err = NewNodeMiddle(siblingKey, midKey).Key()
			if err != nil {
				return nil, err
			}
		} else {
			midKey, err = NewNodeMiddle(midKey, siblingKey).Key()
			if err != nil {
				return nil, err
			}
		}
	}
	return midKey, nil
}
