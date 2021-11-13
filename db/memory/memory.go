package memory

import (
	"bytes"
	"context"
	"sort"

	"github.com/iden3/go-merkletree-sql"
)

// Storage implements the db.Storage interface
type Storage struct {
	prefix      []byte
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

// Get retrieves a value from a key in the db.Storage
func (m *Storage) Get(key []byte) (*merkletree.Node, error) {
	if v, ok := m.kv.Get(merkletree.Concat(m.prefix, key[:])); ok {
		return &v, nil
	}
	return nil, merkletree.ErrNotFound
}

// Put inserts new node into merkletree
func (m *Storage) Put(_ context.Context, key []byte,
	node *merkletree.Node) error {
	m.kv.Put(merkletree.Concat(m.prefix, key), *node)
	return nil
}

// GetRoot returns current merkletree root
func (m *Storage) GetRoot() (*merkletree.Hash, error) {
	if m.currentRoot != nil {
		hash := merkletree.Hash{}
		copy(hash[:], m.currentRoot[:])
		return &hash, nil
	}
	return nil, merkletree.ErrNotFound
}

// SetRoot updates current merkletree root
func (m *Storage) SetRoot(_ context.Context, hash *merkletree.Hash) error {
	root := &merkletree.Hash{}
	copy(root[:], hash[:])
	m.currentRoot = root
	return nil
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
