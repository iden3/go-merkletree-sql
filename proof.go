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
	// Existence indicates whether this is a proof of existence or
	// non-existence
	Existence bool
	// siblings is a list of non-empty sibling keys
	siblings []*Hash
	// Auxiliary node if needed. The filed can return when p.Existence = false.
	// Represent node that exists on position instead expected key.
	// On case when on expected position exists NullableNode, NodeAux will nil.
	NodeAux *NodeAux
}

// proofJSON defines the required elements for MT proof in json serializable structure
type proofJSON struct {
	// existence indicates whether this is a proof of existence or
	// non-existence
	Existence bool `json:"existence"`
	// Siblings is a list of all sibling keys
	Siblings []*Hash `json:"siblings"`
	// Auxiliary node if needed
	NodeAux *NodeAux `json:"node_aux,omitempty"`
}

// NewProofFromData reconstructs proof from siblings and auxiliary node
func NewProofFromData(existence bool,
	allSiblings []*Hash,
	nodeAux *NodeAux) (*Proof, error) {
	var p Proof
	p.Existence = existence
	p.NodeAux = nodeAux
	p.siblings = make([]*Hash, len(allSiblings))
	copy(p.siblings, allSiblings)
	return &p, nil
}

// Bytes serializes a Proof into a byte array.
func (p *Proof) Bytes() []byte {
	bsLen := proofFlagsLen + ElemBytesLen*len(p.siblings)
	if p.NodeAux != nil {
		bsLen += 2 * ElemBytesLen
	}
	bs := make([]byte, bsLen)

	if !p.Existence {
		bs[0] |= 0x01
	}
	bs[1] = byte(len(p.siblings))
	siblingsBytes := bs[proofFlagsLen:]
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

// Siblings returns proof's siblings.
func (p *Proof) Siblings() []*Hash {
	res := make([]*Hash, len(p.siblings))
	copy(res, p.siblings)
	return res
}

// MarshalJSON implements json.Marshaler interface
func (p *Proof) MarshalJSON() ([]byte, error) {
	obj := proofJSON{
		Existence: p.Existence,
		Siblings:  p.siblings,
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

	return nil
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
	path := getPath(len(proof.siblings), kHash[:])
	var siblingKey *Hash
	for lvl := len(proof.siblings) - 1; lvl >= 0; lvl-- {
		siblingKey = proof.siblings[lvl]
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
