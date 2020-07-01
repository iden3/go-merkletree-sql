package merkletree

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-core/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTree(t *testing.T) {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154854", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "13563340744765267202993741297198970774200042973817962221376874695587906013050", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t, "16970503620176669663662021947486532860010370357132361783766545149750777353066", mt.Root().BigInt().String())

	proof, err := mt.GenerateProof(big.NewInt(33), nil)
	assert.Nil(t, err)

	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(33), big.NewInt(44)))
	assert.True(t, !VerifyProof(mt.Root(), proof, big.NewInt(33), big.NewInt(45)))
}

func TestSiblingsFromProof(t *testing.T) {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 64; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	proof, err := mt.GenerateProof(big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}

	siblings := SiblingsFromProof(proof)
	assert.Equal(t, 6, len(siblings))
	assert.Equal(t, "26bc69cfd3c982eba7b45cd2e6a2c75f218c546089f115777df47ab06f1fdb23", siblings[0].Hex())
	assert.Equal(t, "ba7fbb5841bc8fa65193c124fbda4843aaa8d64d4132c79e7176cbed4de65621", siblings[1].Hex())
	assert.Equal(t, "1339329b2d15e467ec3734ec06f6f4ae5a7c8c0b6ba98c26558b5a4db3e9a804", siblings[2].Hex())
	assert.Equal(t, "b2261e6f47d9feb6fac2480928cc0fe03204d946cbc0a7b4de250d3e1384f40f", siblings[3].Hex())
	assert.Equal(t, "b6c905f21c9928efa19a2c4e55d88d5fd0af493032f5b84620eb872e48ff5d01", siblings[4].Hex())
	assert.Equal(t, "69873a951f49bbaff71039d672ffe52d73605aed6b40c1ce7ab068ad86a44d1e", siblings[5].Hex())
}
