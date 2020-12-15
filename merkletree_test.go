package merkletree

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
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
	assert.Equal(t, "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", h.Hex())

	b1, err := NewBigIntFromHashBytes(b.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, new(big.Int).SetBytes(b.Bytes()).String(), b1.String())

	b2, err := NewHashFromBytes(b.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, b.String(), b2.BigInt().String())

	h2, err := NewHashFromHex(h.Hex())
	assert.Nil(t, err)
	assert.Equal(t, h, h2)
	_, err = NewHashFromHex("0x12")
	assert.NotNil(t, err)

	// check limits
	a := new(big.Int).Sub(constants.Q, big.NewInt(1))
	testHashParsers(t, a)
	a = big.NewInt(int64(1))
	testHashParsers(t, a)
}

func testHashParsers(t *testing.T, a *big.Int) {
	require.True(t, cryptoUtils.CheckBigIntInField(a))
	h := NewHashFromBigInt(a)
	assert.Equal(t, a, h.BigInt())
	hFromBytes, err := NewHashFromBytes(h.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, h, hFromBytes)
	assert.Equal(t, a, hFromBytes.BigInt())
	assert.Equal(t, a.String(), hFromBytes.BigInt().String())
	hFromHex, err := NewHashFromHex(h.Hex())
	assert.Nil(t, err)
	assert.Equal(t, h, hFromHex)

	aBIFromHBytes, err := NewBigIntFromHashBytes(h.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, a, aBIFromHBytes)
	assert.Equal(t, new(big.Int).SetBytes(a.Bytes()).String(), aBIFromHBytes.String())
}

func TestNewTree(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "6449712043256457369579901840927028403950625973089336675272087704159094984964", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "11404118908468506234838877883514126008995570353394659302846433035311596046064", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t, "12841932325181810040554102151615400973767747666110051836366805309524360490677", mt.Root().BigInt().String())

	dbRoot, err := mt.dbGetRoot()
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)

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
	assert.Equal(t, "268e25964aa9d6ba42d66ae9eb44b5528540acb19a3644d1367d8c6f7cb23006", mt1.Root().Hex())
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
	k, v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(10), k)
	assert.Equal(t, big.NewInt(20), v)

	k, v, _, err = mt.Get(big.NewInt(15))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(15), k)
	assert.Equal(t, big.NewInt(30), v)

	k, v, _, err = mt.Get(big.NewInt(16))
	assert.NotNil(t, err)
	assert.Equal(t, ErrKeyNotFound, err)
	assert.Equal(t, "0", k.String())
	assert.Equal(t, "0", v.String())
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
	_, v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	_, err = mt.Update(big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)
	_, v, _, err = mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(1024), v)

	_, err = mt.Update(big.NewInt(1000), big.NewInt(1024))
	assert.Equal(t, ErrKeyNotFound, err)

	dbRoot, err := mt.dbGetRoot()
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)
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
	assert.Equal(t, "5b478bdd58595ead03ebf494a74014cbb576ba0d9456aa0916885b9eefae592f", siblings[0].Hex())
	assert.Equal(t, "c1e8ab120a4e475ea1bf00633228bfb9d248f7ddec2aa6367f98d0defb9fb22e", siblings[1].Hex())
	assert.Equal(t, "f4dafd8ac2b9165adc3f6d125af67d5a4d8a7a263dcc90a373d0338929e16e0c", siblings[2].Hex())
	assert.Equal(t, "a94aa346bd85f96aba2e85b67920e44fe6ed767b0e13bea602784e0b8b897515", siblings[3].Hex())
	assert.Equal(t, "54791d7514030ded79301dbf221f5bf186facbc5800912411852fdc101b7151d", siblings[4].Hex())
	assert.Equal(t, "435d28bc0511f8feb93b5f1649a049b460947702ce0baaefcf596175370fe01e", siblings[5].Hex())
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
	assert.Equal(t, "0003000000000000000000000000000000000000000000000000000000000007a6d6b46fefe213a6b579844a1bb7ab5c2db4a13f8662d9c5e729c36728f42730211ddfcc8d30ebd157d1d6912769b8e4abdca41e5dc2b57b026a361c091a8c14c748530e61bf8ea80c987657c3d24b134ece1ef8e2d4bd3f74437bf4392a6b1e", hex.EncodeToString(proof.Bytes()))

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
	assert.Equal(t, "0303000000000000000000000000000000000000000000000000000000000007a6d6b46fefe213a6b579844a1bb7ab5c2db4a13f8662d9c5e729c36728f42730211ddfcc8d30ebd157d1d6912769b8e4abdca41e5dc2b57b026a361c091a8c14c748530e61bf8ea80c987657c3d24b134ece1ef8e2d4bd3f74437bf4392a6b1e04000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Bytes()))

	// Non-existence proof, diff. node aux
	proof, _, err = mt.GenerateProof(big.NewInt(10), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	assert.True(t, proof.NodeAux != nil)
	assert.True(t, VerifyProof(mt.Root(), proof, big.NewInt(10), big.NewInt(0)))
	assert.Equal(t, "0303000000000000000000000000000000000000000000000000000000000007a6d6b46fefe213a6b579844a1bb7ab5c2db4a13f8662d9c5e729c36728f42730e667e2ca15909c4a23beff18e3cc74348fbd3c1a4c765a5bbbca126c9607a42b77e008a73926f1280f8531b139dc1cacf8d83fcec31d405f5c51b7cbddfe152902000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(proof.Bytes()))
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

	_ = mt.Add(big.NewInt(1), big.NewInt(0))
	_ = mt.Add(big.NewInt(2), big.NewInt(0))
	_ = mt.Add(big.NewInt(3), big.NewInt(0))
	_ = mt.Add(big.NewInt(4), big.NewInt(0))
	_ = mt.Add(big.NewInt(5), big.NewInt(0))
	_ = mt.Add(big.NewInt(100), big.NewInt(0))

	// mt.PrintGraphViz(nil)

	expected := `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
"16053348..." -> {"19137630..." "14119616..."}
"19137630..." -> {"19543983..." "19746229..."}
"19543983..." -> {"empty0" "65773153..."}
"empty0" [style=dashed,label=0];
"65773153..." -> {"73498412..." "empty1"}
"empty1" [style=dashed,label=0];
"73498412..." -> {"53169236..." "empty2"}
"empty2" [style=dashed,label=0];
"53169236..." -> {"73522717..." "34811870..."}
"73522717..." [style=filled];
"34811870..." [style=filled];
"19746229..." [style=filled];
"14119616..." -> {"19419204..." "15569531..."}
"19419204..." -> {"78154875..." "34589916..."}
"78154875..." [style=filled];
"34589916..." [style=filled];
"15569531..." [style=filled];
}
`
	w := bytes.NewBufferString("")
	err = mt.GraphViz(w, nil)
	assert.Nil(t, err)
	assert.Equal(t, []byte(expected), w.Bytes())
}

func TestDelete(t *testing.T) {
	mt, err := NewMerkleTree(memory.NewMemoryStorage(), 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "6449712043256457369579901840927028403950625973089336675272087704159094984964", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "11404118908468506234838877883514126008995570353394659302846433035311596046064", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t, "12841932325181810040554102151615400973767747666110051836366805309524360490677", mt.Root().BigInt().String())

	// mt.PrintGraphViz(nil)

	err = mt.Delete(big.NewInt(33))
	// mt.PrintGraphViz(nil)
	assert.Nil(t, err)
	assert.Equal(t, "16195585003843604118922861401064871511855368913846540536604351220077317790615", mt.Root().BigInt().String())

	err = mt.Delete(big.NewInt(1234))
	assert.Nil(t, err)
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	dbRoot, err := mt.dbGetRoot()
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)
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

	assert.Equal(t, "6701939280963330813043570145125351311131831356446202146710280245621673558344", mt.Root().BigInt().String())
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "10304354743004778619823249005484018655542356856535590307973732141291410579841", mt.Root().BigInt().String())

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

	assert.Equal(t, "6989694633650442615746486460134957295274675622748484439660143938730686550248", mt.Root().BigInt().String())
	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "1192610901536912535888866440319084773171371421781091005185759505381507049136", mt.Root().BigInt().String())

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
	assert.Equal(t, "11404118908468506234838877883514126008995570353394659302846433035311596046064", mt.Root().BigInt().String())

	err = mt.Delete(big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "12802904154263054831102426711825443668153853847661287611768065280921698471037", mt.Root().BigInt().String())

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

	q1 := new(big.Int).Sub(constants.Q, big.NewInt(1))
	for i := 0; i < 10; i++ {
		// use numbers near under Q
		k := new(big.Int).Sub(q1, big.NewInt(int64(i)))
		v := big.NewInt(0)
		err = mt.Add(k, v)
		require.Nil(t, err)

		// use numbers near above 0
		k = big.NewInt(int64(i))
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
	cpp, err := mt.AddAndGetCircomProof(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "0", cpp.OldRoot.String())
	assert.Equal(t, "64497120...", cpp.NewRoot.String())
	assert.Equal(t, "0", cpp.OldKey.String())
	assert.Equal(t, "0", cpp.OldValue.String())
	assert.Equal(t, "1", cpp.NewKey.String())
	assert.Equal(t, "2", cpp.NewValue.String())
	assert.Equal(t, true, cpp.IsOld0)
	assert.Equal(t, "[0 0 0 0 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.maxLevels+1, len(cpp.Siblings))

	cpp, err = mt.AddAndGetCircomProof(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "64497120...", cpp.OldRoot.String())
	assert.Equal(t, "11404118...", cpp.NewRoot.String())
	assert.Equal(t, "1", cpp.OldKey.String())
	assert.Equal(t, "2", cpp.OldValue.String())
	assert.Equal(t, "33", cpp.NewKey.String())
	assert.Equal(t, "44", cpp.NewValue.String())
	assert.Equal(t, false, cpp.IsOld0)
	assert.Equal(t, "[0 0 0 0 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.maxLevels+1, len(cpp.Siblings))

	cpp, err = mt.AddAndGetCircomProof(big.NewInt(55), big.NewInt(66))
	assert.Nil(t, err)
	assert.Equal(t, "11404118...", cpp.OldRoot.String())
	assert.Equal(t, "18284203...", cpp.NewRoot.String())
	assert.Equal(t, "0", cpp.OldKey.String())
	assert.Equal(t, "0", cpp.OldValue.String())
	assert.Equal(t, "55", cpp.NewKey.String())
	assert.Equal(t, "66", cpp.NewValue.String())
	assert.Equal(t, true, cpp.IsOld0)
	assert.Equal(t, "[0 42948778... 0 0 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.maxLevels+1, len(cpp.Siblings))
}

func TestUpdateCircomProcessorProof(t *testing.T) {
	mt := newTestingMerkle(t, 10)
	defer mt.db.Close()

	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	_, v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	cpp, err := mt.Update(big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)
	assert.Equal(t, "14895645...", cpp.OldRoot.String())
	assert.Equal(t, "75223641...", cpp.NewRoot.String())
	assert.Equal(t, "10", cpp.OldKey.String())
	assert.Equal(t, "20", cpp.OldValue.String())
	assert.Equal(t, "10", cpp.NewKey.String())
	assert.Equal(t, "1024", cpp.NewValue.String())
	assert.Equal(t, false, cpp.IsOld0)
	assert.Equal(t, "[19625419... 46910949... 18399594... 20473908... 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
}

func TestTypesMarshalers(t *testing.T) {
	// test Hash marshalers
	h, err := NewHashFromString("42")
	assert.Nil(t, err)
	s, err := json.Marshal(h)
	assert.Nil(t, err)
	var h2 *Hash
	err = json.Unmarshal(s, &h2)
	assert.Nil(t, err)
	assert.Equal(t, h, h2)

	// create CircomProcessorProof
	mt := newTestingMerkle(t, 10)
	defer mt.db.Close()
	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}
	_, v, _, err := mt.Get(big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)
	cpp, err := mt.Update(big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)

	// test CircomProcessorProof marshalers
	b, err := json.Marshal(&cpp)
	assert.Nil(t, err)

	var cpp2 *CircomProcessorProof
	err = json.Unmarshal(b, &cpp2)
	assert.Nil(t, err)
	assert.Equal(t, cpp, cpp2)
}
