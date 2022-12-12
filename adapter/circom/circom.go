package circom

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v3"
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
	Fnc      int
}

func (c *CircomVerifierProof) MarshalJSON() ([]byte, error) {
	cjson := circomVerifierProofJSON{
		Root:     c.Root.String(),
		OldKey:   c.OldKey.String(),
		OldValue: c.OldValue.String(),
		IsOld0:   c.IsOld0,
		Key:      c.Key.String(),
		Value:    c.Value.String(),
		Fnc:      c.Fnc,
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
	c.Fnc = cjson.Fnc

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
	key, err := merkletree.NewHashFromBigInt(k)
	if err != nil {
		return nil, err
	}
	value, err := merkletree.NewHashFromBigInt(v)
	if err != nil {
		return nil, err
	}
	cd := &ConvertData{
		Proof:   p,
		RootKey: rootKey,
		Key:     key,
		Value:   value,
		Depth:   mt.MaxLevels(),
	}
	return ProofToCircomFormat(cd), nil
}

type ConvertData struct {
	Proof   *merkletree.Proof
	RootKey *merkletree.Hash
	Key     *merkletree.Hash
	Value   *merkletree.Hash
	Depth   int
}

// ProofToCircomFormat convert merkletree.Proof to circom compatible proof.
func ProofToCircomFormat(src *ConvertData) *CircomVerifierProof {
	dst := new(CircomVerifierProof)
	dst.Root = src.RootKey
	dst.Siblings = src.Proof.Siblings()
	if src.Proof.NodeAux == nil {
		if !src.Proof.Existence {
			dst.IsOld0 = true
			dst.Fnc = 1 // non inclusion
		} else {
			dst.Fnc = 0 // inclusion
		}
		dst.OldKey = &merkletree.HashZero
		dst.OldValue = &merkletree.HashZero
	} else {
		dst.OldKey = src.Proof.NodeAux.Key
		dst.OldValue = src.Proof.NodeAux.Value
		dst.Fnc = 1 // non inclusion
	}
	dst.Key = src.Key
	dst.Value = src.Value

	dst.Siblings = merkletree.ZeroPaddedSiblings(dst.Siblings, src.Depth)
	return dst
}
