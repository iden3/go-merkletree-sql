package merkletree

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-merkletree/db/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var debug = false

type Fatalable interface {
	Fatal(args ...interface{})
}

func newTestingMerkle(f Fatalable, numLevels int) *MerkleTree {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), numLevels)
	if err != nil {
		f.Fatal(err)
		return nil
	}
	return mt
}

func TestHashParsers(t *testing.T) {
	h0 := NewHashFromBigInt(big.NewInt(0))
	assert.Equal(t, "0", h0.String())
	h1 := NewHashFromBigInt(big.NewInt(1))
	assert.Equal(t, "1", h1.String())
	h10 := NewHashFromBigInt(big.NewInt(10))
	assert.Equal(t, "10", h10.String())

	h7l := NewHashFromBigInt(big.NewInt(1234567))
	assert.Equal(t, "1234567", h7l.String())
	h8l := NewHashFromBigInt(big.NewInt(12345678))
	assert.Equal(t, "12345678...", h8l.String())

	b, ok := new(big.Int).SetString("4932297968297298434239270129193057052722409868268166443802652458940273154854", 10)
	assert.True(t, ok)
	h := NewHashFromBigInt(b)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154854", h.BigInt().String())
	assert.Equal(t, "49322979...", h.String())
	assert.Equal(t, "0ae794eb9c3d8bbb9002e993fc2ed301dcbd2af5508ed072c375e861f1aa5b26", h.Hex())
}

func TestNewTree(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
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

	proof, v, err := mt.GenerateProof(big.NewInt(33), nil)
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(44), v)

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
	assert.Equal(t, "0967b777d660e54aa3a0f0f3405bb962504d3d69d6b930146cd212dff9913bee", mt1.Root().Hex())
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

func TestGet(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()

	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	v, _, err = mt.Get(big.NewInt(15))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(30), v)

	v, _, err = mt.Get(big.NewInt(16))
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyNotFound, err)
	assert.Nil(t, v)
}

func TestUpdate(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()

	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	_, err = mt.Update(big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)
	v, _, err = mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(1024), v)

	_, err = mt.Update(big.NewInt(1000), big.NewInt(1024))
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestUpdate2(t *testing.T) {
	mt1 := newTestingMerkle(t, 140)
	defer mt1.db.Close()
	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()

	err := mt1.Add(big.NewInt(1), big.NewInt(119))
	assert.Nil(t, err)
	err = mt1.Add(big.NewInt(2), big.NewInt(229))
	assert.Nil(t, err)
	err = mt1.Add(big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	err = mt2.Add(big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	err = mt2.Add(big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	err = mt2.Add(big.NewInt(9876), big.NewInt(10))
	assert.Nil(t, err)

	_, err = mt1.Update(big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	_, err = mt1.Update(big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	_, err = mt2.Update(big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	assert.Equal(t, mt1.Root(), mt2.Root())
}

func TestGenerateAndVerifyProof128(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 128; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	proof, v, err := mt.GenerateProof(big.NewInt(42), nil)
	assert.Nil(t, err)
	assert.Equal(t, "0", v.String())
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(42), big.NewInt(0)))
}

func TestTreeLimit(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 5)
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
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 64; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	proof, _, err := mt.GenerateProof(big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}

	siblings := SiblingsFromProof(proof)
	assert.Equal(t, 6, len(siblings))
	assert.Equal(t, "23db1f6fb07af47d7715f18960548c215fc7a2e6d25cb4a7eb82c9d3cf69bc26", siblings[0].Hex())
	assert.Equal(t, "2156e64dedcb76719ec732414dd6a8aa4348dafb24c19351a68fbc4158bb7fba", siblings[1].Hex())
	assert.Equal(t, "04a8e9b34d5a8b55268ca96b0b8c7c5aaef4f606ec3437ec67e4152d9b323913", siblings[2].Hex())
	assert.Equal(t, "0ff484133e0d25deb4a7c0cb46d90432e00fcc280948c2fab6fed9476f1e26b2", siblings[3].Hex())
	assert.Equal(t, "015dff482e87eb2046b8f5323049afd05f8dd8554e2c9aa1ef28991cf205c9b6", siblings[4].Hex())
	assert.Equal(t, "1e4da486ad68b07acec1406bed5a60732de5ff72d63910f7afbb491f953a8769", siblings[5].Hex())
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

	proof, _, err := mt.GenerateProof(big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(4), big.NewInt(0)))
	assert.Equal(t, "000300000000000000000000000000000000000000000000000000000000000728ea2b267d2a9436657f20b5827285175e030f58c07375535106903b16621630b9104d995843c7cffa685009a1b28dcd371022a3b27b3a4d6987f7c8b39b0f2fffc165330710754ca0fc24451bdd5d5f82a05f42f1427fbdf17879c0b84be60f", hex.EncodeToString(proof.Bytes()))

	for i := 8; i < 32; i++ {
		proof, _, err = mt.GenerateProof(big.NewInt(int64(i)), nil)
		assert.Nil(t, err)
		if debug {
			fmt.Println(i, proof)
		}
	}
	// Non-existence proof, empty aux
	proof, _, err = mt.GenerateProof(big.NewInt(12), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	// assert.True(t, proof.nodeAux == nil)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(12), big.NewInt(0)))
	assert.Equal(t, "030300000000000000000000000000000000000000000000000000000000000728ea2b267d2a9436657f20b5827285175e030f58c07375535106903b16621630b9104d995843c7cffa685009a1b28dcd371022a3b27b3a4d6987f7c8b39b0f2fffc165330710754ca0fc24451bdd5d5f82a05f42f1427fbdf17879c0b84be60f04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Bytes()))

	// Non-existence proof, diff. node aux
	proof, _, err = mt.GenerateProof(big.NewInt(10), nil)
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
	proof, _, err := mt.GenerateProof(big.NewInt(int64(4)), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t, !VerifyProof(mt.Root(), proof, big.NewInt(int64(5)), big.NewInt(int64(5))))

	// Invalid non-existence proof (Non-existence proof, diff. node aux)
	proof, _, err = mt.GenerateProof(big.NewInt(int64(4)), nil)
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

func TestGraphViz(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)

	mt.Add(big.NewInt(1), big.NewInt(0))
	mt.Add(big.NewInt(2), big.NewInt(0))
	mt.Add(big.NewInt(3), big.NewInt(0))
	mt.Add(big.NewInt(4), big.NewInt(0))
	mt.Add(big.NewInt(5), big.NewInt(0))
	mt.Add(big.NewInt(100), big.NewInt(0))

	// mt.PrintGraphViz(nil)

	expected := `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
"60195538..." -> {"19759736..." "18893277..."}
"19759736..." -> {"16152312..." "43945008..."}
"16152312..." -> {"empty0" "13952255..."}
"empty0" [style=dashed,label=0];
"13952255..." -> {"61769925..." "empty1"}
"empty1" [style=dashed,label=0];
"61769925..." -> {"92723289..." "empty2"}
"empty2" [style=dashed,label=0];
"92723289..." -> {"21082735..." "82784818..."}
"21082735..." [style=filled];
"82784818..." [style=filled];
"43945008..." [style=filled];
"18893277..." -> {"19855703..." "17718670..."}
"19855703..." -> {"11499909..." "15828714..."}
"11499909..." [style=filled];
"15828714..." [style=filled];
"17718670..." [style=filled];
}
`
	w := bytes.NewBufferString("")
	mt.GraphViz(w, nil)
	assert.Equal(t, []byte(expected), w.Bytes())
}

func TestDelete(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
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

	// mt.PrintGraphViz(nil)

	err = mt.Delete(big.NewInt(33))
	// mt.PrintGraphViz(nil)
	assert.Nil(t, err)
	assert.Equal(t, "12820263606494630162816839760750120928463716794691735985748071431547370997091", mt.Root().BigInt().String())

	err = mt.Delete(big.NewInt(1234))
	assert.Nil(t, err)
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

}

func TestDelete2(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()
	for i := 0; i < 8; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	expectedRoot := mt.Root()

	k := big.NewInt(8)
	v := big.NewInt(0)
	err := mt.Add(k, v)
	require.Nil(t, err)

	err = mt.Delete(big.NewInt(8))
	assert.Nil(t, err)
	assert.Equal(t, expectedRoot, mt.Root())

	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()
	for i := 0; i < 8; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt2.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete3(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()

	err := mt.Add(big.NewInt(1), big.NewInt(1))
	assert.Nil(t, err)

	err = mt.Add(big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)

	assert.Equal(t, "2427629547967522489273866134471574861207714751136138191708011221765688788661", mt.Root().BigInt().String())
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "10822920717809411688334493481050035035708810950159417482558569847174767667301", mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()
	err = mt2.Add(big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete4(t *testing.T) {
	mt := newTestingMerkle(t, 140)
	defer mt.db.Close()

	err := mt.Add(big.NewInt(1), big.NewInt(1))
	assert.Nil(t, err)

	err = mt.Add(big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)

	err = mt.Add(big.NewInt(3), big.NewInt(3))
	assert.Nil(t, err)

	assert.Equal(t, "16614298246517994771186095530428786749320098419259206061045083278756632941513", mt.Root().BigInt().String())
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "6117330520107511783353383870014397665359816230889739699667943862706617498952", mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()
	err = mt2.Add(big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)
	err = mt2.Add(big.NewInt(3), big.NewInt(3))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete5(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)

	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "13563340744765267202993741297198970774200042973817962221376874695587906013050", mt.Root().BigInt().String())

	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "12075524681474630909546786277734445038384732558409197537058769521806571391765", mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, 140)
	defer mt2.db.Close()
	err = mt2.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDeleteNonExistingKeys(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)

	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)

	err = mt.Delete(big.NewInt(33))
	assert.Nil(t, err)
	err = mt.Delete(big.NewInt(33))
	assert.Equal(t, ErrKeyNotFound, err)

	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)

	assert.Equal(t, "0", mt.Root().String())

	err = mt.Delete(big.NewInt(33))
	assert.Equal(t, ErrKeyNotFound, err)
}

func TestDumpLeafsImportLeafs(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt.db.Close()

	for i := 0; i < 10; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		err = mt.Add(k, v)
		require.Nil(t, err)
	}

	d, err := mt.DumpLeafs(nil)
	assert.Nil(t, err)

	mt2, err := NewMerkleTree(memory.NewMemoryStorage(), 140)
	require.Nil(t, err)
	defer mt2.db.Close()
	err = mt2.ImportDumpedLeafs(d)
	assert.Nil(t, err)

	assert.Equal(t, mt.Root(), mt2.Root())
}

func TestAddAndGetCircomProof(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	_, err = mt.AddAndGetCircomProof(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154854", mt.Root().BigInt().String())

	_, err = mt.AddAndGetCircomProof(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "13563340744765267202993741297198970774200042973817962221376874695587906013050", mt.Root().BigInt().String())

	_, err = mt.AddAndGetCircomProof(big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t, "16970503620176669663662021947486532860010370357132361783766545149750777353066", mt.Root().BigInt().String())

	proof, v, err := mt.GenerateProof(big.NewInt(33), nil)
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(44), v)

	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(33), big.NewInt(44)))
	assert.True(t, !VerifyProof(mt.Root(), proof, big.NewInt(33), big.NewInt(45)))
}
