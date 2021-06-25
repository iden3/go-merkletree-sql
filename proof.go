package merkletree

import (
	"bytes"
	"fmt"
	"math/big"
)

// Proof defines the required elements for a MT proof of existence or
// non-existence.
type Proof struct {
	// existence indicates wether this is a proof of existence or
	// non-existence.
	Existence bool
	// depth indicates how deep in the tree the proof goes.
	depth uint
	// notempties is a bitmap of non-empty Siblings found in Siblings.
	notempties [ElemBytesLen - proofFlagsLen]byte
	// Siblings is a list of non-empty sibling keys.
	Siblings []*Hash
	NodeAux  *NodeAux
}

// NewProofFromBytes parses a byte array into a Proof.
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
			copy(sib[:], siblingBytes[sibIdx*ElemBytesLen:(sibIdx+1)*ElemBytesLen])
			p.Siblings = append(p.Siblings, &sib)
			sibIdx++
		}
	}

	if !p.Existence && ((bs[0] & 0x02) != 0) {
		p.NodeAux = &NodeAux{Key: &Hash{}, Value: &Hash{}}
		nodeAuxBytes := siblingBytes[len(p.Siblings)*ElemBytesLen:]
		if len(nodeAuxBytes) != 2*ElemBytesLen {
			return nil, ErrInvalidProofBytes
		}
		copy(p.NodeAux.Key[:], nodeAuxBytes[:ElemBytesLen])
		copy(p.NodeAux.Value[:], nodeAuxBytes[ElemBytesLen:2*ElemBytesLen])
	}
	return p, nil
}

// Bytes serializes a Proof into a byte array.
func (p *Proof) Bytes() []byte {
	bsLen := proofFlagsLen + len(p.notempties) + ElemBytesLen*len(p.Siblings)
	if p.NodeAux != nil {
		bsLen += 2 * ElemBytesLen //nolint:gomnd
	}
	bs := make([]byte, bsLen)

	if !p.Existence {
		bs[0] |= 0x01
	}
	bs[1] = byte(p.depth)
	copy(bs[proofFlagsLen:len(p.notempties)+proofFlagsLen], p.notempties[:])
	siblingsBytes := bs[len(p.notempties)+proofFlagsLen:]
	for i, k := range p.Siblings {
		copy(siblingsBytes[i*ElemBytesLen:(i+1)*ElemBytesLen], k[:])
	}
	if p.NodeAux != nil {
		bs[0] |= 0x02
		copy(bs[len(bs)-2*ElemBytesLen:], p.NodeAux.Key[:])
		copy(bs[len(bs)-1*ElemBytesLen:], p.NodeAux.Value[:])
	}
	return bs
}

// SiblingsFromProof returns all the siblings of the proof.
func SiblingsFromProof(proof *Proof) []*Hash {
	sibIdx := 0
	siblings := []*Hash{}
	for lvl := 0; lvl < int(proof.depth); lvl++ {
		if TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblings = append(siblings, proof.Siblings[sibIdx])
			sibIdx++
		} else {
			siblings = append(siblings, &HashZero)
		}
	}
	return siblings
}

// AllSiblings returns all the siblings of the proof.
func (p *Proof) AllSiblings() []*Hash {
	return SiblingsFromProof(p)
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
	kHash := NewHashFromBigInt(k)
	vHash := NewHashFromBigInt(v)
	sibIdx := len(proof.Siblings) - 1
	var err error
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
			siblingKey = proof.Siblings[sibIdx]
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
