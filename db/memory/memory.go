package memory

import (
	"bytes"
	"github.com/iden3/go-merkletree"
	"sort"
)

// Storage implements the db.Storage interface
type Storage struct {
	prefix      []byte
	kv          merkletree.KvMap
	currentRoot *merkletree.Hash
}

// StorageTx implements the db.Tx interface
type StorageTx struct {
	s           *Storage
	kv          merkletree.KvMap
	currentRoot *merkletree.Hash
}

// NewMemoryStorage returns a new Storage
func NewMemoryStorage() *Storage {
	kvmap := make(merkletree.KvMap)
	return &Storage{[]byte{}, kvmap, nil}
}

// WithPrefix implements the method WithPrefix of the interface db.Storage
func (m *Storage) WithPrefix(prefix []byte) merkletree.Storage {
	return &Storage{merkletree.Concat(m.prefix, prefix), m.kv, nil}
}

// NewTx implements the method NewTx of the interface db.Storage
func (m *Storage) NewTx() (merkletree.Tx, error) {
	return &StorageTx{m, make(merkletree.KvMap), nil}, nil
}

// Get retrieves a value from a key in the db.Storage
func (m *Storage) Get(key []byte) (*merkletree.Node, error) {
	if v, ok := m.kv.Get(merkletree.Concat(m.prefix, key[:])); ok {
		return &v, nil
	}
	return nil, merkletree.ErrNotFound
}

func (m *Storage) GetRoot() (*merkletree.Hash, error) {
	if m.currentRoot != nil {
		hash := merkletree.Hash{}
		copy(hash[:], m.currentRoot[:])
		return &hash, nil
	}
	return nil, merkletree.ErrNotFound
}

// Iterate implements the method Iterate of the interface db.Storage
func (m *Storage) Iterate(f func([]byte, *merkletree.Node) (bool, error)) error {
	kvs := make([]merkletree.KV, 0)
	for _, v := range m.kv {
		if len(v.K) < len(m.prefix) ||
			!bytes.Equal(v.K[:len(m.prefix)], m.prefix) {
			continue
		}
		localkey := v.K[len(m.prefix):]
		kvs = append(kvs, merkletree.KV{K: localkey, V: v.V})
	}
	sort.SliceStable(kvs, func(i, j int) bool {
		return bytes.Compare(kvs[i].K, kvs[j].K) < 0
	})

	for _, kv := range kvs {
		if cont, err := f(kv.K, &kv.V); err != nil {
			return err
		} else if !cont {
			break
		}
	}
	return nil
}

// Get implements the method Get of the interface db.Tx
func (tx *StorageTx) Get(key []byte) (*merkletree.Node, error) {
	if v, ok := tx.kv.Get(merkletree.Concat(tx.s.prefix, key)); ok {
		return &v, nil
	}
	if v, ok := tx.s.kv.Get(merkletree.Concat(tx.s.prefix, key)); ok {
		return &v, nil
	}

	return nil, merkletree.ErrNotFound
}

// Put implements the method Put of the interface db.Tx
func (tx *StorageTx) Put(k []byte, v *merkletree.Node) error {
	tx.kv.Put(merkletree.Concat(tx.s.prefix, k), *v)
	return nil
}

func (tx *StorageTx) GetRoot() (*merkletree.Hash, error) {
	if tx.currentRoot != nil {
		hash := merkletree.Hash{}
		copy(hash[:], tx.currentRoot[:])
		return &hash, nil
	}
	return nil, merkletree.ErrNotFound
}

// SetRoot sets a hash of merkle tree root in the interface db.Tx
func (tx *StorageTx) SetRoot(hash *merkletree.Hash) error {

	// TODO: do tx.Put('currentroot', hash) here ?

	root := &merkletree.Hash{}
	copy(root[:], hash[:])
	tx.currentRoot = root
	return nil
}

// Commit implements the method Commit of the interface db.Tx
func (tx *StorageTx) Commit() error {
	for _, v := range tx.kv {
		tx.s.kv.Put(v.K, v.V)
	}
	//if tx.currentRoot == nil {
	//	tx.currentRoot = &merkletree.Hash{}
	//}
	tx.s.currentRoot = tx.currentRoot
	tx.kv = nil
	return nil
}

// Add implements the method Add of the interface db.Tx
func (tx *StorageTx) Add(atx merkletree.Tx) error {
	mstx := atx.(*StorageTx)
	for _, v := range mstx.kv {
		tx.kv.Put(v.K, v.V)
	}
	return nil
}

// Close implements the method Close of the interface db.Tx
func (tx *StorageTx) Close() {
	tx.kv = nil
}

// Close implements the method Close of the interface db.Storage
func (m *Storage) Close() {
}

// List implements the method List of the interface db.Storage
func (m *Storage) List(limit int) ([]merkletree.KV, error) {
	ret := []merkletree.KV{}
	err := m.Iterate(func(key []byte, value *merkletree.Node) (bool, error) {
		ret = append(ret, merkletree.KV{K: merkletree.Clone(key), V: *value})
		if len(ret) == limit {
			return false, nil
		}
		return true, nil
	})
	return ret, err
}
