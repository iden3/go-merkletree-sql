//nolint:gomnd,golint
package test

import (
	"github.com/iden3/go-merkletree"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestReturnKnownErrIfNotExists checks that the implementation of the
// db.Storage interface returns the expected error in the case that the value
// is not found
func TestReturnKnownErrIfNotExists(t *testing.T, sto merkletree.Storage) {
	k := []byte("key")

	tx, err := sto.NewTx()
	//defer func() {
	//	tx.Close()
	//	sto.Close()
	//}()

	assert.Nil(t, err)
	_, err = tx.Get(k)
	assert.EqualError(t, err, merkletree.ErrNotFound.Error())
}

// TestStorageInsertGet checks that the implementation of the db.Storage
// interface behaves as expected
func TestStorageInsertGet(t *testing.T, sto merkletree.Storage) {
	key := []byte("key")
	value := merkletree.Hash{1, 1, 1, 1}

	tx, err := sto.NewTx()
	//defer func() {
	//	tx.Close()
	//	sto.Close()
	//}()
	assert.Nil(t, err)
	node := merkletree.NewNodeMiddle(&value, &value)
	err = tx.Put(key, node)
	assert.Nil(t, err)
	v, err := tx.Get(key)
	assert.Nil(t, err)
	assert.Equal(t, value, *v.ChildL)
	assert.Equal(t, value, *v.ChildR)
	assert.Nil(t, tx.Commit())

	tx, err = sto.NewTx()
	assert.Nil(t, err)
	v, err = tx.Get(key)
	assert.Nil(t, err)
	assert.Equal(t, value, *v.ChildL)
	assert.Equal(t, value, *v.ChildR)
}

// TestStorageWithPrefix checks that the implementation of the db.Storage
// interface behaves as expected for the WithPrefix method
func TestStorageWithPrefix(t *testing.T, sto merkletree.Storage) {
	k := []byte{9}

	sto1 := sto.WithPrefix([]byte{1})
	sto2 := sto.WithPrefix([]byte{2})

	// check within tx

	sto1tx, err := sto1.NewTx()
	assert.Nil(t, err)
	node := merkletree.NewNodeLeaf(&merkletree.Hash{1, 2, 3}, &merkletree.Hash{4, 5, 6})
	err = sto1tx.Put(k, node)
	assert.Nil(t, err)
	v1, err := sto1tx.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, merkletree.Hash{4, 5, 6}, *v1.Entry[1])
	assert.Nil(t, sto1tx.Commit())

	sto2tx, err := sto2.NewTx()
	assert.Nil(t, err)
	node.Entry[1] = &merkletree.Hash{9, 10}
	err = sto2tx.Put(k, node)
	assert.Nil(t, err)
	v2, err := sto2tx.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, merkletree.Hash{9, 10}, *v2.Entry[1])
	assert.Nil(t, sto2tx.Commit())

	// check outside tx

	v1, err = sto1.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, merkletree.Hash{4, 5, 6}, *v1.Entry[1])

	v2, err = sto2.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, merkletree.Hash{9, 10}, *v2.Entry[1])
}

// TestIterate checks that the implementation of the db.Storage interface
// behaves as expected for the Iterate method
func TestIterate(t *testing.T, sto merkletree.Storage) {
	r := []merkletree.KV{}
	lister := func(k []byte, v *merkletree.Node) (bool, error) {
		r = append(r, merkletree.KV{K: merkletree.Clone(k), V: *v})
		return true, nil
	}

	sto1 := sto.WithPrefix([]byte{1})
	err := sto1.Iterate(lister)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r))

	sto1tx, _ := sto1.NewTx()
	err = sto1tx.Put([]byte{1}, merkletree.NewNodeMiddle(&merkletree.Hash{4}, &merkletree.Hash{5}))
	assert.Nil(t, err)
	err = sto1tx.Put([]byte{2}, merkletree.NewNodeMiddle(&merkletree.Hash{5}, &merkletree.Hash{6}))
	assert.Nil(t, err)
	err = sto1tx.Put([]byte{3}, merkletree.NewNodeMiddle(&merkletree.Hash{6}, &merkletree.Hash{7}))
	assert.Nil(t, err)
	assert.Nil(t, sto1tx.Commit())

	sto2 := sto.WithPrefix([]byte{2})
	sto2tx, _ := sto2.NewTx()
	err = sto2tx.Put([]byte{1}, merkletree.NewNodeMiddle(&merkletree.Hash{7}, &merkletree.Hash{8}))
	assert.Nil(t, err)
	err = sto2tx.Put([]byte{2}, merkletree.NewNodeMiddle(&merkletree.Hash{8}, &merkletree.Hash{9}))
	assert.Nil(t, err)
	err = sto2tx.Put([]byte{3}, merkletree.NewNodeMiddle(&merkletree.Hash{9}, &merkletree.Hash{10}))
	assert.Nil(t, err)
	assert.Nil(t, sto2tx.Commit())

	r = []merkletree.KV{}
	err = sto1.Iterate(lister)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(r))
	assert.Equal(t, merkletree.KV{K: []byte{1}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{4}, &merkletree.Hash{5})}, r[0])
	assert.Equal(t, merkletree.KV{K: []byte{2}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{5}, &merkletree.Hash{6})}, r[1])
	assert.Equal(t, merkletree.KV{K: []byte{3}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{6}, &merkletree.Hash{7})}, r[2])

	r = []merkletree.KV{}
	err = sto2.Iterate(lister)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(r))
	assert.Equal(t, merkletree.KV{K: []byte{1}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{7}, &merkletree.Hash{8})}, r[0])
	assert.Equal(t, merkletree.KV{K: []byte{2}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{8}, &merkletree.Hash{9})}, r[1])
	assert.Equal(t, merkletree.KV{K: []byte{3}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{9}, &merkletree.Hash{10})}, r[2])
}

// TestConcatTx checks that the implementation of the db.Storage interface
// behaves as expected
func TestConcatTx(t *testing.T, sto merkletree.Storage) {
	k := []byte{9}

	sto1 := sto.WithPrefix([]byte{1})
	sto2 := sto.WithPrefix([]byte{2})

	// check within tx

	sto1tx, err := sto1.NewTx()
	if err != nil {
		panic(err)
	}
	err = sto1tx.Put(k, merkletree.NewNodeLeaf(&merkletree.Hash{4, 5, 6}, &merkletree.Hash{7, 8, 9}))
	assert.Nil(t, err)
	sto2tx, err := sto2.NewTx()
	if err != nil {
		panic(err)
	}
	err = sto2tx.Put(k, merkletree.NewNodeLeaf(&merkletree.Hash{8, 9}, &merkletree.Hash{10, 11}))
	assert.Nil(t, err)

	err = sto1tx.Add(sto2tx)
	assert.Nil(t, err)
	assert.Nil(t, sto1tx.Commit())

	// check outside tx

	v1, err := sto1.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, v1, merkletree.NewNodeLeaf(&merkletree.Hash{4, 5, 6}, &merkletree.Hash{7, 8, 9}))

	v2, err := sto2.Get(k)
	assert.Nil(t, err)
	assert.Equal(t, v2, merkletree.NewNodeLeaf(&merkletree.Hash{8, 9}, &merkletree.Hash{10, 11}))
}

// TestList checks that the implementation of the db.Storage interface behaves
// as expected
func TestList(t *testing.T, sto merkletree.Storage) {
	sto1 := sto.WithPrefix([]byte{1})
	r1, err := sto1.List(100)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(r1))

	sto1tx, _ := sto1.NewTx()
	err = sto1tx.Put([]byte{1}, merkletree.NewNodeMiddle(&merkletree.Hash{4}, &merkletree.Hash{5}))
	assert.Nil(t, err)
	err = sto1tx.Put([]byte{2}, merkletree.NewNodeMiddle(&merkletree.Hash{5}, &merkletree.Hash{6}))
	assert.Nil(t, err)
	err = sto1tx.Put([]byte{3}, merkletree.NewNodeMiddle(&merkletree.Hash{6}, &merkletree.Hash{7}))
	assert.Nil(t, err)
	assert.Nil(t, sto1tx.Commit())

	sto2 := sto.WithPrefix([]byte{2})
	sto2tx, _ := sto2.NewTx()
	err = sto2tx.Put([]byte{1}, merkletree.NewNodeMiddle(&merkletree.Hash{7}, &merkletree.Hash{8}))
	assert.Nil(t, err)
	err = sto2tx.Put([]byte{2}, merkletree.NewNodeMiddle(&merkletree.Hash{8}, &merkletree.Hash{9}))
	assert.Nil(t, err)
	err = sto2tx.Put([]byte{3}, merkletree.NewNodeMiddle(&merkletree.Hash{9}, &merkletree.Hash{10}))
	assert.Nil(t, err)
	assert.Nil(t, sto2tx.Commit())

	r, err := sto1.List(100)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(r))
	assert.Equal(t, r[0], merkletree.KV{K: []byte{1}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{4}, &merkletree.Hash{5})})
	assert.Equal(t, r[1], merkletree.KV{K: []byte{2}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{5}, &merkletree.Hash{6})})
	assert.Equal(t, r[2], merkletree.KV{K: []byte{3}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{6}, &merkletree.Hash{7})})

	r, err = sto1.List(2)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(r))
	assert.Equal(t, r[0], merkletree.KV{K: []byte{1}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{4}, &merkletree.Hash{5})})
	assert.Equal(t, r[1], merkletree.KV{K: []byte{2}, V: *merkletree.NewNodeMiddle(&merkletree.Hash{5}, &merkletree.Hash{6})})
}
