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
	cp, err := GenerateSCVerifierProof(ctx, k, rootKey, mt)
	if err != nil {
		return nil, err
	}
	cp.Siblings = merkletree.ZeroPaddedSiblings(cp.Siblings, mt.MaxLevels())
	return cp, nil
}

// GenerateSCVerifierProof returns the CircomVerifierProof for a certain key in
// the MerkleTree with the Siblings without the extra 0 needed at the circom
// circuits, which makes it straight forward to verifiy inside a Smart
// Contract.  If the rootKey is nil, the current merkletree root is used.
func GenerateSCVerifierProof(ctx context.Context, k *big.Int,
	rootKey *merkletree.Hash, mt *merkletree.MerkleTree) (*CircomVerifierProof, error) {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	p, v, err := mt.GenerateProof(ctx, k, rootKey)
	if err != nil && err != merkletree.ErrKeyNotFound {
		return nil, err
	}
	var cp CircomVerifierProof
	cp.Root = rootKey
	cp.Siblings = p.Siblings()
	if p.NodeAux == nil {
		if !p.Existence {
			cp.IsOld0 = true
			cp.Fnc = 1 // non inclusion
		} else {
			cp.Fnc = 0 // inclusion
		}

		cp.OldKey = &merkletree.HashZero
		cp.OldValue = &merkletree.HashZero
	} else {
		cp.OldKey = p.NodeAux.Key
		cp.OldValue = p.NodeAux.Value
		cp.Fnc = 1 // non inclusion
	}
	cp.Key, err = merkletree.NewHashFromBigInt(k)
	if err != nil {
		return nil, err
	}
	cp.Value, err = merkletree.NewHashFromBigInt(v)
	if err != nil {
		return nil, err
	}

	return &cp, nil
}
