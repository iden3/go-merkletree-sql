//nolint:golint
package test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var debug = false

func newTestingMerkle(t *testing.T, sto merkletree.Storage,
	numLevels int) *merkletree.MerkleTree {
	mt, err := merkletree.NewMerkleTree(context.Background(), sto, numLevels)
	require.NoError(t, err)
	return mt
}

type StorageBuilder interface {
	NewStorage(t *testing.T) merkletree.Storage
}

func TestAll(t *testing.T, sb StorageBuilder) {
	t.Run("TestReturnKnownErrIfNotExists", func(t *testing.T) {
		TestReturnKnownErrIfNotExists(t, sb.NewStorage(t))
	})
	t.Run("TestStorageInsertGet", func(t *testing.T) {
		TestStorageInsertGet(t, sb.NewStorage(t))
	})
	t.Run("TestNewTree", func(t *testing.T) {
		TestNewTree(t, sb.NewStorage(t))
	})
	t.Run("TestTreeRootWithOneNode", func(t *testing.T) {
		TestTreeRootWithOneNode(t, sb.NewStorage(t))
	})
	t.Run("TestAddDifferentOrder", func(t *testing.T) {
		TestAddDifferentOrder(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestAddRepeatedIndex", func(t *testing.T) {
		TestAddRepeatedIndex(t, sb.NewStorage(t))
	})
	t.Run("TestGet", func(t *testing.T) {
		TestGet(t, sb.NewStorage(t))
	})
	t.Run("TestUpdate", func(t *testing.T) {
		TestUpdate(t, sb.NewStorage(t))
	})
	t.Run("TestUpdate2", func(t *testing.T) {
		TestUpdate2(t, sb.NewStorage(t))
	})
	t.Run("TestGenerateAndVerifyProof128", func(t *testing.T) {
		TestGenerateAndVerifyProof128(t, sb.NewStorage(t))
	})
	t.Run("TestTreeLimit", func(t *testing.T) {
		TestTreeLimit(t, sb.NewStorage(t))
	})
	t.Run("TestSiblingsFromProof", func(t *testing.T) {
		TestSiblingsFromProof(t, sb.NewStorage(t))
	})
	t.Run("TestVerifyProofCases", func(t *testing.T) {
		TestVerifyProofCases(t, sb.NewStorage(t))
	})
	t.Run("TestVerifyProofFalse", func(t *testing.T) {
		TestVerifyProofFalse(t, sb.NewStorage(t))
	})
	t.Run("TestDelete", func(t *testing.T) {
		TestDelete(t, sb.NewStorage(t))
	})
	t.Run("TestDelete2", func(t *testing.T) {
		TestDelete2(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestDelete3", func(t *testing.T) {
		TestDelete3(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestDelete4", func(t *testing.T) {
		TestDelete4(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestDelete5", func(t *testing.T) {
		TestDelete5(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestDeleteNonExistingKeys", func(t *testing.T) {
		TestDeleteNonExistingKeys(t, sb.NewStorage(t))
	})
	t.Run("TestDumpLeafsImportLeafs", func(t *testing.T) {
		TestDumpLeafsImportLeafs(t, sb.NewStorage(t), sb.NewStorage(t))
	})
	t.Run("TestAddAndGetCircomProof", func(t *testing.T) {
		TestAddAndGetCircomProof(t, sb.NewStorage(t))
	})
	t.Run("TestUpdateCircomProcessorProof", func(t *testing.T) {
		TestUpdateCircomProcessorProof(t, sb.NewStorage(t))
	})
	t.Run("TestSmtVerifier", func(t *testing.T) {
		TestSmtVerifier(t, sb.NewStorage(t))
	})
	t.Run("TestTypesMarshalers", func(t *testing.T) {
		TestTypesMarshalers(t, sb.NewStorage(t))
	})
}

// TestReturnKnownErrIfNotExists checks that the implementation of the
// db.Storage interface returns the expected error in the case that the value
// is not found
func TestReturnKnownErrIfNotExists(t *testing.T, sto merkletree.Storage) {
	k := []byte("key")
	_, err := sto.Get(context.Background(), k)
	assert.EqualError(t, err, merkletree.ErrNotFound.Error())
}

// TestStorageInsertGet checks that the implementation of the db.Storage
// interface behaves as expected
func TestStorageInsertGet(t *testing.T, sto merkletree.Storage) {
	value := merkletree.Hash{1, 1, 1, 1}

	node := merkletree.NewNodeMiddle(&value, &value)
	key, err := node.Key()
	assert.NoError(t, err)
	ctx := context.Background()
	err = sto.Put(ctx, key[:], node)
	assert.NoError(t, err)
	v, err := sto.Get(ctx, key[:])
	assert.NoError(t, err)
	assert.Equal(t, value, *v.ChildL)
	assert.Equal(t, value, *v.ChildR)

	v, err = sto.Get(ctx, key[:])
	assert.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, value, *v.ChildL)
	assert.Equal(t, value, *v.ChildR)
}

//
// TODO: Add tests for each storage
//

func TestNewTree(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t,
		"13578938674299138072471463694055224830892726234048532520316387704878000008795",
		mt.Root().BigInt().String())

	err = mt.Add(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t,
		"5412393676474193513566895793055462193090331607895808993925969873307089394741",
		mt.Root().BigInt().String())

	err = mt.Add(ctx, big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t,
		"14204494359367183802864593755198662203838502594566452929175967972147978322084",
		mt.Root().BigInt().String())

	dbRoot, err := sto.GetRoot(ctx)
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)

	proof, v, err := mt.GenerateProof(ctx, big.NewInt(33), nil)
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(44), v)

	assert.True(t, merkletree.VerifyProof(
		mt.Root(), proof, big.NewInt(33), big.NewInt(44)))
	assert.True(t, !merkletree.VerifyProof(
		mt.Root(), proof, big.NewInt(33), big.NewInt(45)))
}

func TestTreeRootWithOneNode(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	err = mt.Add(ctx, big.NewInt(100), big.NewInt(200))
	assert.Nil(t, err)
	assert.Equal(t,
		"798876344175601936808542466911896801961231313012372360729165540443724338832",
		mt.Root().BigInt().String())

	inputs := []*big.Int{
		big.NewInt(100), // key
		big.NewInt(200), // value
		big.NewInt(1),
	}
	res, _ := poseidon.Hash(inputs)
	assert.Equal(t, mt.Root().BigInt().String(), res.String())
}

func TestAddDifferentOrder(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	ctx := context.Background()

	mt1 := newTestingMerkle(t, sto, 140)
	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt1.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	mt2 := newTestingMerkle(t, sto2, 140)
	for i := 16 - 1; i >= 0; i-- {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt2.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	assert.Equal(t, mt1.Root().Hex(), mt2.Root().Hex())
	assert.Equal(t,
		"3b89100bec24da9275c87bc188740389e1d5accfc7d88ba5688d7fa96a00d82f",
		mt1.Root().Hex())
}

func TestAddRepeatedIndex(t *testing.T, sto merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)
	k := big.NewInt(int64(3))
	v := big.NewInt(int64(12))
	ctx := context.Background()
	if err := mt.Add(ctx, k, v); err != nil {
		t.Fatal(err)
	}
	err := mt.Add(ctx, k, v)
	assert.NotNil(t, err)
	assert.Equal(t, err, merkletree.ErrEntryIndexAlreadyExists)
}

func TestGet(t *testing.T, sto merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()
	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	k, v, _, err := mt.Get(ctx, big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(10), k)
	assert.Equal(t, big.NewInt(20), v)

	k, v, _, err = mt.Get(ctx, big.NewInt(15))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(15), k)
	assert.Equal(t, big.NewInt(30), v)

	k, v, _, err = mt.Get(ctx, big.NewInt(16))
	assert.NotNil(t, err)
	assert.Equal(t, merkletree.ErrKeyNotFound, err)
	assert.Equal(t, "0", k.String())
	assert.Equal(t, "0", v.String())
}

func TestUpdate(t *testing.T, sto merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()

	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	_, v, _, err := mt.Get(ctx, big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	_, err = mt.Update(ctx, big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)
	_, v, _, err = mt.Get(ctx, big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(1024), v)

	_, err = mt.Update(ctx, big.NewInt(1000), big.NewInt(1024))
	assert.Equal(t, merkletree.ErrKeyNotFound, err)

	dbRoot, err := sto.GetRoot(ctx)
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)
}

func TestUpdate2(t *testing.T, sto merkletree.Storage) {
	mt1 := newTestingMerkle(t, sto, 140)
	mt2 := newTestingMerkle(t, sto, 140)

	ctx := context.Background()

	err := mt1.Add(ctx, big.NewInt(1), big.NewInt(119))
	assert.Nil(t, err)
	err = mt1.Add(ctx, big.NewInt(2), big.NewInt(229))
	assert.Nil(t, err)
	err = mt1.Add(ctx, big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	err = mt2.Add(ctx, big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	err = mt2.Add(ctx, big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	err = mt2.Add(ctx, big.NewInt(9876), big.NewInt(10))
	assert.Nil(t, err)

	_, err = mt1.Update(ctx, big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	_, err = mt1.Update(ctx, big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	_, err = mt2.Update(ctx, big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	assert.Equal(t, mt1.Root(), mt2.Root())
}

func TestGenerateAndVerifyProof128(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 140)
	require.Nil(t, err)

	for i := 0; i < 128; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	proof, v, err := mt.GenerateProof(ctx, big.NewInt(42), nil)
	assert.Nil(t, err)
	assert.Equal(t, "0", v.String())
	assert.True(t, merkletree.VerifyProof(
		mt.Root(), proof, big.NewInt(42), big.NewInt(0)))
}

func TestTreeLimit(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 5)
	require.Nil(t, err)

	for i := 0; i < 16; i++ {
		err = mt.Add(ctx, big.NewInt(int64(i)), big.NewInt(int64(i)))
		assert.Nil(t, err)
	}

	// here the tree is full, should not allow to add more data as reaches the maximum number of levels
	err = mt.Add(ctx, big.NewInt(int64(16)), big.NewInt(int64(16)))
	assert.NotNil(t, err)
	assert.Equal(t, merkletree.ErrReachedMaxLevel, err)
}

func TestSiblingsFromProof(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 140)
	require.Nil(t, err)

	for i := 0; i < 64; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}

	siblings := merkletree.SiblingsFromProof(proof)
	assert.Equal(t, 6, len(siblings))
	assert.Equal(t,
		"d6e368bda90c5ee3e910222c1fc1c0d9e23f2d350dbc47f4a92de30f1be3c60b",
		siblings[0].Hex())
	assert.Equal(t,
		"9dbd03b1bcd580e0f3e6668d80d55288f04464126feb1624ec8ee30be8df9c16",
		siblings[1].Hex())
	assert.Equal(t,
		"de866af9545dcd1c5bb7811e7f27814918e037eb9fead40919e8f19525896e27",
		siblings[2].Hex())
	assert.Equal(t,
		"5f4182212a84741d1174ba7c42e369f2e3ad8ade7d04eea2d0f98e3ed8b7a317",
		siblings[3].Hex())
	assert.Equal(t,
		"77639098d513f7aef9730fdb1d1200401af5fe9da91b61772f4dd142ac89a122",
		siblings[4].Hex())
	assert.Equal(t,
		"943ee501f4ba2137c79b54af745dfc5f105f539fcc449cd2a356eb5c030e3c07",
		siblings[5].Hex())
}

func TestVerifyProofCases(t *testing.T, sto merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()
	for i := 0; i < 8; i++ {
		if err := mt.Add(ctx, big.NewInt(int64(i)), big.NewInt(0)); err != nil {
			t.Fatal(err)
		}
	}

	// Existence proof
	proof, _, err := mt.GenerateProof(ctx, big.NewInt(4), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t,
		merkletree.VerifyProof(mt.Root(), proof, big.NewInt(4), big.NewInt(0)))
	assert.Equal(t,
		"0003000000000000000000000000000000000000000000000000000000000007529cbedbda2bdd25fd6455551e55245fa6dc11a9d0c27dc0cd38fca44c17e40344ad686a18ba78b502c0b6f285c5c8393bde2f7a3e2abe586515e4d84533e3037b062539bde2d80749746986cf8f0001fd2cdbf9a89fcbf981a769daef49df06", //nolint:lll
		hex.EncodeToString(proof.Bytes()))

	for i := 8; i < 32; i++ {
		proof, _, err = mt.GenerateProof(ctx, big.NewInt(int64(i)), nil)
		assert.Nil(t, err)
		if debug {
			fmt.Println(i, proof)
		}
	}
	// Non-existence proof, empty aux
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(12), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	// assert.True(t, proof.nodeAux == nil)
	assert.True(t,
		merkletree.VerifyProof(mt.Root(), proof, big.NewInt(12), big.NewInt(0)))
	assert.Equal(t,
		"0303000000000000000000000000000000000000000000000000000000000007529cbedbda2bdd25fd6455551e55245fa6dc11a9d0c27dc0cd38fca44c17e40344ad686a18ba78b502c0b6f285c5c8393bde2f7a3e2abe586515e4d84533e3037b062539bde2d80749746986cf8f0001fd2cdbf9a89fcbf981a769daef49df0604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", //nolint:lll
		hex.EncodeToString(proof.Bytes()))

	// Non-existence proof, diff. node aux
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(10), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, false)
	assert.True(t, proof.NodeAux != nil)
	assert.True(t,
		merkletree.VerifyProof(mt.Root(), proof, big.NewInt(10), big.NewInt(0)))
	assert.Equal(t,
		"0303000000000000000000000000000000000000000000000000000000000007529cbedbda2bdd25fd6455551e55245fa6dc11a9d0c27dc0cd38fca44c17e4030acfcdd2617df9eb5aef744c5f2e03eb8c92c61f679007dc1f2707fd908ea41a9433745b469c101edca814c498e7f388100d497b24f1d2ac935bced3572f591d02000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", //nolint:lll
		hex.EncodeToString(proof.Bytes()))
}

func TestVerifyProofFalse(t *testing.T, sto merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()
	for i := 0; i < 8; i++ {
		if err := mt.Add(ctx, big.NewInt(int64(i)), big.NewInt(0)); err != nil {
			t.Fatal(err)
		}
	}

	// Invalid existence proof (node used for verification doesn't
	// correspond to node in the proof)
	proof, _, err := mt.GenerateProof(ctx, big.NewInt(int64(4)), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	assert.True(t, !merkletree.VerifyProof(mt.Root(), proof,
		big.NewInt(int64(5)), big.NewInt(int64(5))))

	// Invalid non-existence proof (Non-existence proof, diff. node aux)
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(int64(4)), nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, proof.Existence, true)
	// Now we change the proof from existence to non-existence, and add e's
	// data as auxiliary node.
	proof.Existence = false
	proof.NodeAux = &merkletree.NodeAux{
		Key:   hashFromInt(big.NewInt(int64(4))),
		Value: hashFromInt(big.NewInt(4))}
	assert.True(t,
		!merkletree.VerifyProof(mt.Root(), proof, big.NewInt(int64(4)),
			big.NewInt(0)))
}

func hashFromInt(in *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(in)
	if err != nil {
		panic(err)
	}
	return h
}

func TestDelete(t *testing.T, sto merkletree.Storage) {
	mt, err := merkletree.NewMerkleTree(context.Background(), sto, 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())
	ctx := context.Background()

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t,
		"13578938674299138072471463694055224830892726234048532520316387704878000008795",
		mt.Root().BigInt().String())

	err = mt.Add(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t,
		"5412393676474193513566895793055462193090331607895808993925969873307089394741",
		mt.Root().BigInt().String())

	err = mt.Add(ctx, big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t,
		"14204494359367183802864593755198662203838502594566452929175967972147978322084",
		mt.Root().BigInt().String())

	// mt.PrintGraphViz(nil)

	err = mt.Delete(ctx, big.NewInt(33))
	// mt.PrintGraphViz(nil)
	assert.Nil(t, err)
	assert.Equal(t,
		"15550352095346187559699212771793131433118240951738528922418613687814377955591",
		mt.Root().BigInt().String())

	err = mt.Delete(ctx, big.NewInt(1234))
	assert.Nil(t, err)
	err = mt.Delete(ctx, big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	dbRoot, err := sto.GetRoot(ctx)
	require.Nil(t, err)
	assert.Equal(t, mt.Root(), dbRoot)
}

func TestDelete2(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	ctx := context.Background()
	mt := newTestingMerkle(t, sto, 140)
	for i := 0; i < 8; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}

	expectedRoot := mt.Root()

	k := big.NewInt(8)
	v := big.NewInt(0)
	err := mt.Add(ctx, k, v)
	require.Nil(t, err)

	err = mt.Delete(ctx, big.NewInt(8))
	assert.Nil(t, err)
	assert.Equal(t, expectedRoot, mt.Root())

	mt2 := newTestingMerkle(t, sto2, 140)
	for i := 0; i < 8; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(0)
		if err := mt2.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete3(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()
	err := mt.Add(ctx, big.NewInt(1), big.NewInt(1))
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)

	assert.Equal(t,
		"19060075022714027595905950662613111880864833370144986660188929919683258088314",
		mt.Root().BigInt().String())
	err = mt.Delete(ctx, big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t,
		"849831128489032619062850458217693666094013083866167024127442191257793527951",
		mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, sto2, 140)
	err = mt2.Add(ctx, big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete4(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	mt := newTestingMerkle(t, sto, 140)

	ctx := context.Background()
	err := mt.Add(ctx, big.NewInt(1), big.NewInt(1))
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(3), big.NewInt(3))
	assert.Nil(t, err)

	assert.Equal(t,
		"14109632483797541575275728657193822866549917334388996328141438956557066918117",
		mt.Root().BigInt().String())
	err = mt.Delete(ctx, big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t,
		"159935162486187606489815340465698714590556679404589449576549073038844694972",
		mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, sto2, 140)
	err = mt2.Add(ctx, big.NewInt(2), big.NewInt(2))
	assert.Nil(t, err)
	err = mt2.Add(ctx, big.NewInt(3), big.NewInt(3))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDelete5(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 10)
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	err = mt.Add(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t,
		"5412393676474193513566895793055462193090331607895808993925969873307089394741",
		mt.Root().BigInt().String())

	err = mt.Delete(ctx, big.NewInt(1))
	assert.Nil(t, err)
	assert.Equal(t,
		"18869260084287237667925661423624848342947598951870765316380602291081195309822",
		mt.Root().BigInt().String())

	mt2 := newTestingMerkle(t, sto2, 140)
	err = mt2.Add(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, mt2.Root(), mt.Root())
}

func TestDeleteNonExistingKeys(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 10)
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	err = mt.Add(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)

	err = mt.Delete(ctx, big.NewInt(33))
	assert.Nil(t, err)
	err = mt.Delete(ctx, big.NewInt(33))
	assert.Equal(t, merkletree.ErrKeyNotFound, err)

	err = mt.Delete(ctx, big.NewInt(1))
	assert.Nil(t, err)

	assert.Equal(t, "0", mt.Root().String())

	err = mt.Delete(ctx, big.NewInt(33))
	assert.Equal(t, merkletree.ErrKeyNotFound, err)
}

func TestDumpLeafsImportLeafs(t *testing.T, sto merkletree.Storage,
	sto2 merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 140)
	require.Nil(t, err)

	q1 := new(big.Int).Sub(constants.Q, big.NewInt(1))
	for i := 0; i < 10; i++ {
		// use numbers near under Q
		k := new(big.Int).Sub(q1, big.NewInt(int64(i)))
		v := big.NewInt(0)
		err = mt.Add(ctx, k, v)
		require.Nil(t, err)

		// use numbers near above 0
		k = big.NewInt(int64(i))
		err = mt.Add(ctx, k, v)
		require.Nil(t, err)
	}

	d, err := mt.DumpLeafs(ctx, nil)
	assert.Nil(t, err)

	mt2, err := merkletree.NewMerkleTree(ctx, sto2, 140)
	require.Nil(t, err)
	err = mt2.ImportDumpedLeafs(ctx, d)
	assert.Nil(t, err)

	assert.Equal(t, mt.Root(), mt2.Root())
}

func TestAddAndGetCircomProof(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	cpp, err := mt.AddAndGetCircomProof(ctx, big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "0", cpp.OldRoot.String())
	assert.Equal(t,
		"13578938674299138072471463694055224830892726234048532520316387704878000008795",
		cpp.NewRoot.String())
	assert.Equal(t, "0", cpp.OldKey.String())
	assert.Equal(t, "0", cpp.OldValue.String())
	assert.Equal(t, "1", cpp.NewKey.String())
	assert.Equal(t, "2", cpp.NewValue.String())
	assert.Equal(t, true, cpp.IsOld0)
	assert.Equal(t, "[0 0 0 0 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.MaxLevels()+1, len(cpp.Siblings))

	cpp, err = mt.AddAndGetCircomProof(ctx, big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t,
		"13578938674299138072471463694055224830892726234048532520316387704878000008795",
		cpp.OldRoot.String())
	assert.Equal(t,
		"5412393676474193513566895793055462193090331607895808993925969873307089394741",
		cpp.NewRoot.String())
	assert.Equal(t, "1", cpp.OldKey.String())
	assert.Equal(t, "2", cpp.OldValue.String())
	assert.Equal(t, "33", cpp.NewKey.String())
	assert.Equal(t, "44", cpp.NewValue.String())
	assert.Equal(t, false, cpp.IsOld0)
	assert.Equal(t, "[0 0 0 0 0 0 0 0 0 0 0]", fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.MaxLevels()+1, len(cpp.Siblings))

	cpp, err = mt.AddAndGetCircomProof(ctx, big.NewInt(55), big.NewInt(66))
	assert.Nil(t, err)
	assert.Equal(t,
		"5412393676474193513566895793055462193090331607895808993925969873307089394741",
		cpp.OldRoot.String())
	assert.Equal(t,
		"5094364082618099436543535513148866130251600642297988457797401489780171282025",
		cpp.NewRoot.String())
	assert.Equal(t, "0", cpp.OldKey.String())
	assert.Equal(t, "0", cpp.OldValue.String())
	assert.Equal(t, "55", cpp.NewKey.String())
	assert.Equal(t, "66", cpp.NewValue.String())
	assert.Equal(t, true, cpp.IsOld0)
	assert.Equal(t,
		"[0 "+
			"21312042436525850949775663177240566532157857119003189090405819719191539342280"+
			" 0 0 0 0 0 0 0 0 0]",
		fmt.Sprintf("%v", cpp.Siblings))
	assert.Equal(t, mt.MaxLevels()+1, len(cpp.Siblings))
}

func TestUpdateCircomProcessorProof(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt := newTestingMerkle(t, sto, 10)

	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	_, v, _, err := mt.Get(ctx, big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	cpp, err := mt.Update(ctx, big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)
	assert.Equal(t, "3901088098157312895771168508102875327412498476307103941861116446804059788045",
		cpp.OldRoot.String())
	assert.Equal(t, "18587862578201383535363956627488622136678432340275446723812600963773389007517",
		cpp.NewRoot.String())
	assert.Equal(t, "10", cpp.OldKey.String())
	assert.Equal(t, "20", cpp.OldValue.String())
	assert.Equal(t, "10", cpp.NewKey.String())
	assert.Equal(t, "1024", cpp.NewValue.String())
	assert.Equal(t, false, cpp.IsOld0)
	assert.Equal(t,
		"[3493055760199345983787399479799897884337329583575225430469748865784580035592"+
			" 20201609720365205433999360001442791710365537253733030676534981802168302054263 "+
			"18790542149740435554763618183910097219145811410462734411095932062387939731734 "+
			"15930030482599007570177067416534114035267479078907080052418814162004846408322 "+
			"0 0 0 0 0 0 0]",
		fmt.Sprintf("%v", cpp.Siblings))
}

func TestSmtVerifier(t *testing.T, sto merkletree.Storage) {
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, sto, 4)
	assert.Nil(t, err)

	err = mt.Add(ctx, big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)

	cvp, err := mt.GenerateSCVerifierProof(ctx, big.NewInt(1), nil)
	assert.Nil(t, err)
	jCvp, err := json.Marshal(cvp)
	assert.Nil(t, err)
	// expect siblings to be '[]', instead of 'null'
	expected := `{"root":"6525056641794203554583616941316772618766382307684970171204065038799368146416","siblings":[],"oldKey":"0","oldValue":"0","isOld0":false,"key":"1","value":"11","fnc":0}` //nolint:lll

	assert.Equal(t, expected, string(jCvp))
	err = mt.Add(ctx, big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	err = mt.Add(ctx, big.NewInt(3), big.NewInt(33))
	assert.Nil(t, err)
	err = mt.Add(ctx, big.NewInt(4), big.NewInt(44))
	assert.Nil(t, err)

	cvp, err = mt.GenerateCircomVerifierProof(ctx, big.NewInt(2), nil)
	assert.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	assert.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Expect siblings with the extra 0 that the circom circuits need
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700","0","0","0"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	assert.Equal(t, expected, string(jCvp))

	cvp, err = mt.GenerateSCVerifierProof(ctx, big.NewInt(2), nil)
	assert.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	assert.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Without the extra 0 that the circom circuits need, but that are not
	// needed at a smart contract verification
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	assert.Equal(t, expected, string(jCvp))
}

func TestTypesMarshalers(t *testing.T, sto merkletree.Storage) {
	// test Hash marshalers
	h, err := merkletree.NewHashFromString("42")
	assert.Nil(t, err)
	s, err := json.Marshal(h)
	assert.Nil(t, err)
	var h2 *merkletree.Hash
	err = json.Unmarshal(s, &h2)
	assert.Nil(t, err)
	assert.Equal(t, h, h2)

	ctx := context.Background()

	// create CircomProcessorProof
	mt := newTestingMerkle(t, sto, 10)
	for i := 0; i < 16; i++ {
		k := big.NewInt(int64(i))
		v := big.NewInt(int64(i * 2))
		if err := mt.Add(ctx, k, v); err != nil {
			t.Fatal(err)
		}
	}
	_, v, _, err := mt.Get(ctx, big.NewInt(10))
	assert.Nil(t, err)
	assert.Equal(t, big.NewInt(20), v)
	cpp, err := mt.Update(ctx, big.NewInt(10), big.NewInt(1024))
	assert.Nil(t, err)

	// test CircomProcessorProof marshalers
	b, err := json.Marshal(&cpp)
	assert.Nil(t, err)

	var cpp2 *merkletree.CircomProcessorProof
	err = json.Unmarshal(b, &cpp2)
	assert.Nil(t, err)
	assert.Equal(t, cpp, cpp2)
}
