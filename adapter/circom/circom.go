package circom

import (
	"context"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v3"
)

// CircomVerifierProof defines the VerifierProof compatible with circom. Is the
// data of the proof that a certain leaf exists in the MerkleTree.
type CircomVerifierProof struct {
	Root     *merkletree.Hash   `json:"root"`
	Siblings []*merkletree.Hash `json:"siblings"`
	OldKey   *merkletree.Hash   `json:"oldKey"`
	OldValue *merkletree.Hash   `json:"oldValue"`
	IsOld0   bool               `json:"isOld0"`
	Key      *merkletree.Hash   `json:"key"`
	Value    *merkletree.Hash   `json:"value"`
	Fnc      int                `json:"fnc"` // 0: inclusion, 1: non inclusion
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
	cp.Siblings = merkletree.CircomSiblingsFromSiblings(cp.Siblings, mt.MaxLevels())
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
	cp.Siblings = p.AllSiblings()
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
