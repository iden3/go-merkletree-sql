package merkletree

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-core/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var debug = false

type Fatalable interface {
	Fatal(args ...interface{})
}

func newTestingMerkle(f Fatalable, numLevels int) *MerkleTree {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), numLevels)
	if err != nil {
		f.Fatal(err)
		return nil
	}
	return mt
}

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

func TestAddDifferentOrder(t *testing.T) {
	mt1 := newTestingMerkle(t, 140)
	defer mt1.db.Close()
	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt1.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()
	for i := 16 - 1; i >= 0; i-- {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt2.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	assert.Equal(t, mt1.Root().Hex(), mt2.Root().Hex())
	assert.Equal(t, "ee3b91f9df12d26c1430b9d6693d4d5062b95b40f3f0a0a34ae560d677b76709", mt1.Root().Hex())
}

func TestAddRepeatedIndex(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()
	k := big.NewInt(int64(3))
	v := big.NewInt(int64(12))
	if err := mt.Add(k, v); err != nil {
		t.Fatal(err)
	}
	err := mt.Add(k, v)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrEntryIndexAlreadyExists)
}

func TestGenerateAndVerifyProof128(t *testing.T) {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 128; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	proof, err := mt.GenerateProof(big.NewInt(42), nil)
	assert.Nil(t, err)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(42), big.NewInt(0)))
}

func TestTreeLimit(t *testing.T) {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), 5)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 16; i++ {
		err = mt.Add(big.NewInt(int64(i)), big.NewInt(int64(i)))
		assert.Nil(t, err)
	}

	// here the tree is full, should not allow to add more data as reaches the maximum number of levels
	err = mt.Add(big.NewInt(int64(16)), big.NewInt(int64(16)))
	assert.NotNil(t, err)
	assert.Equal(t, ErrReachedMaxLevel, err)
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

func TestVerifyProofCases(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.DB().Close()

	for i := 0; i < 8; i++ {
		if err := mt.Add(big.NewInt(int64(i)), big.NewInt(0)); err != nil {
			t.Fatal(err)
		}
	}

	// Existence proof

	proof, err := mt.GenerateProof(big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(4), big.NewInt(0)))
	assert.Equal(t, "000300000000000000000000000000000000000000000000000000000000000728ea2b267d2a9436657f20b5827285175e030f58c07375535106903b16621630b9104d995843c7cffa685009a1b28dcd371022a3b27b3a4d6987f7c8b39b0f2fffc165330710754ca0fc24451bdd5d5f82a05f42f1427fbdf17879c0b84be60f", hex.EncodeToString(proof.Bytes()))

	for i := 8; i < 32; i++ {
		proof, err = mt.GenerateProof(big.NewInt(int64(i)), nil)
		assert.Nil(t, err)
		if debug {
			fmt.Println(i, proof)
		}
	}
	// Non-existence proof, empty aux
	proof, err = mt.GenerateProof(big.NewInt(12), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	// assert.True(t, proof.nodeAux == nil)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(12), big.NewInt(0)))
	assert.Equal(t, "030300000000000000000000000000000000000000000000000000000000000728ea2b267d2a9436657f20b5827285175e030f58c07375535106903b16621630b9104d995843c7cffa685009a1b28dcd371022a3b27b3a4d6987f7c8b39b0f2fffc165330710754ca0fc24451bdd5d5f82a05f42f1427fbdf17879c0b84be60f04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Bytes()))

	// Non-existence proof, diff. node aux
	proof, err = mt.GenerateProof(big.NewInt(10), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	assert.True(t, proof.NodeAux != nil)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(10), big.NewInt(0)))
	assert.Equal(t, "030300000000000000000000000000000000000000000000000000000000000728ea2b267d2a9436657f20b5827285175e030f58c07375535106903b1662163097fcf8f911b271df196e0a75667b8a4f3024ef39f87201ed2b7cda349ba202296b7aeba35dc19ab0d4f65e175536c9952a90b6de18c3205611c3cd4fb408f01602000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Bytes()))
}

func TestVerifyProofFalse(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.DB().Close()

	for i := 0; i < 8; i++ {
		if err := mt.Add(big.NewInt(int64(i)), big.NewInt(0)); err != nil {
			t.Fatal(err)
		}
	}

	// Invalid existence proof (node used for verification doesn't
	// correspond to node in the proof)
	proof, err := mt.GenerateProof(big.NewInt(int64(4)), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t, !VerifyProof(mt.Root(), proof, big.NewInt(int64(5)), big.NewInt(int64(5))))

	// Invalid non-existence proof (Non-existence proof, diff. node aux)
	proof, err = mt.GenerateProof(big.NewInt(int64(4)), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	// Now we change the proof from existence to non-existence, and add e's
	// data as auxiliary node.
	proof.Existence = false
	proof.NodeAux = &NodeAux{Key: NewHashFromBigInt(big.NewInt(int64(4))), Value: NewHashFromBigInt(big.NewInt(4))}
	assert.True(t, !VerifyProof(mt.Root(), proof, big.NewInt(int64(4)), big.NewInt(0)))
}
