package circom

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v3"
)

type ProofType int

const (
	Inclusion = iota
	NonInclusion
)

type circomVerifierProofJSON struct {
	Root     string   `json:"root"`
	Siblings []string `json:"siblings"`
	OldKey   string   `json:"oldKey"`
	OldValue string   `json:"oldValue"`
	IsOld0   bool     `json:"isOld0"`
	Key      string   `json:"key"`
	Value    string   `json:"value"`
	Fnc      int      `json:"fnc"` // 0: inclusion, 1: non inclusion
}

// CircomVerifierProof defines the VerifierProof compatible with circom. Is the
// data of the proof that a certain leaf exists in the MerkleTree.
type CircomVerifierProof struct {
	Root     *merkletree.Hash
	Siblings []*merkletree.Hash
	OldKey   *merkletree.Hash
	OldValue *merkletree.Hash
	IsOld0   bool
	Key      *merkletree.Hash
	Value    *merkletree.Hash
	Fnc      ProofType
}

func (c *CircomVerifierProof) MarshalJSON() ([]byte, error) {
	cjson := circomVerifierProofJSON{
		Root:     c.Root.String(),
		OldKey:   c.OldKey.String(),
		OldValue: c.OldValue.String(),
		IsOld0:   c.IsOld0,
		Key:      c.Key.String(),
		Value:    c.Value.String(),
		Fnc:      int(c.Fnc),
	}
	cjson.Siblings = make([]string, len(c.Siblings))
	for i := range c.Siblings {
		cjson.Siblings[i] = c.Siblings[i].String()
	}

	return json.Marshal(cjson)
}

func (c *CircomVerifierProof) UnmarshalJSON(data []byte) error {
	cjson := new(circomVerifierProofJSON)
	err := json.Unmarshal(data, cjson)
	if err != nil {
		return err
	}

	c.Root, err = merkletree.NewHashFromString(cjson.Root, 10)
	if err != nil {
		return err
	}
	c.OldKey, err = merkletree.NewHashFromString(cjson.OldKey, 10)
	if err != nil {
		return err
	}
	c.OldValue, err = merkletree.NewHashFromString(cjson.OldValue, 10)
	if err != nil {
		return err
	}
	c.IsOld0 = cjson.IsOld0
	c.Key, err = merkletree.NewHashFromString(cjson.Key, 10)
	if err != nil {
		return err
	}
	c.Value, err = merkletree.NewHashFromString(cjson.Value, 10)
	if err != nil {
		return err
	}
	c.Fnc = ProofType(cjson.Fnc)

	c.Siblings = make([]*merkletree.Hash, len(cjson.Siblings))
	for i := range cjson.Siblings {
		c.Siblings[i], err = merkletree.NewHashFromString(cjson.Siblings[i], 10)
		if err != nil {
			return err
		}
	}

	return nil
}

// GenerateCircomVerifierProof returns the CircomVerifierProof for a certain
// key in the MerkleTree.  If the rootKey is nil, the current merkletree root
// is used.
func GenerateCircomVerifierProof(ctx context.Context,
	k *big.Int, rootKey *merkletree.Hash, mt *merkletree.MerkleTree) (*CircomVerifierProof, error) {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	p, v, err := mt.GenerateProof(ctx, k, rootKey)
	if err != nil && err != merkletree.ErrKeyNotFound {
		return nil, err
	}
	return ProofToCircomFormat(p, rootKey, k, v, mt.MaxLevels())
}

// ProofToCircomFormat convert merkletree.Proof to circom compatible proof.
func ProofToCircomFormat(
	proof *merkletree.Proof,
	rootKey *merkletree.Hash,
	key, value *big.Int,
	depth int,
) (*CircomVerifierProof, error) {
	dst := new(CircomVerifierProof)

	var err error
	dst.Key, err = merkletree.NewHashFromBigInt(key)
	if err != nil {
		return nil, err
	}
	dst.Value, err = merkletree.NewHashFromBigInt(value)
	if err != nil {
		return nil, err
	}

	dst.Root = rootKey
	dst.Siblings = proof.Siblings()
	if proof.NodeAux == nil {
		if !proof.Existence {
			dst.IsOld0 = true
			dst.Fnc = 1 // non inclusion
		} else {
			dst.Fnc = 0 // inclusion
		}
		dst.OldKey = &merkletree.HashZero
		dst.OldValue = &merkletree.HashZero
	} else {
		dst.OldKey = proof.NodeAux.Key
		dst.OldValue = proof.NodeAux.Value
		dst.Fnc = 1 // non inclusion
	}

	dst.Siblings = ZeroPaddedSiblings(dst.Siblings, depth)
	return dst, nil
}

// ZeroPaddedSiblings returns the full siblings compatible with circom
func ZeroPaddedSiblings(siblings []*merkletree.Hash, levels int) []*merkletree.Hash {
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &merkletree.HashZero)
	}
	return siblings
}
