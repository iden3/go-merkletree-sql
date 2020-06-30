package merkletree

import (
	"fmt"
	"math/big"

	cryptoConstants "github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// HashElems performs a poseidon hash over the array of ElemBytes.
// Uses poseidon.PoseidonHash to be compatible with the circom circuits
// implementations.
// The maxim slice input size is poseidon.T
func HashElems(elems ...*big.Int) (*Hash, error) {
	if len(elems) > poseidon.T {
		return nil, fmt.Errorf("HashElems input can not be bigger than %v", poseidon.T)
	}

	bi, err := BigIntsToPoseidonInput(elems...)
	if err != nil {
		return nil, err
	}

	poseidonHash, err := poseidon.PoseidonHash(bi)
	if err != nil {
		fmt.Println("ERR HashElems PoseidonHash")
		fmt.Println("e", bi[0])
		fmt.Println("q", cryptoConstants.Q)
		return nil, err
	}
	return NewHashFromBigInt(poseidonHash), nil
}

// HashElemsKey performs a poseidon hash over the array of ElemBytes.
func HashElemsKey(key *big.Int, elems ...*big.Int) (*Hash, error) {
	if len(elems) > poseidon.T-1 {
		return nil, fmt.Errorf("HashElemsKey input can not be bigger than %v", poseidon.T-1)
	}
	if key == nil {
		key = new(big.Int).SetInt64(0)
	}
	bi, err := BigIntsToPoseidonInput(elems...)
	if err != nil {
		return nil, err
	}
	copy(bi[len(elems):], []*big.Int{key})
	poseidonHash, err := poseidon.PoseidonHash(bi)
	if err != nil {
		return nil, err
	}
	return NewHashFromBigInt(poseidonHash), nil
}

func BigIntsToPoseidonInput(bigints ...*big.Int) ([poseidon.T]*big.Int, error) {
	z := big.NewInt(0)
	b := [poseidon.T]*big.Int{z, z, z, z, z, z}
	copy(b[:poseidon.T], bigints[:])

	return b, nil
}
