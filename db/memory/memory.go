package memory

import (
	"context"

	"github.com/iden3/go-merkletree-sql/v2"
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

// Get retrieves a value from a key in the db.Storage
func (m *Storage) Get(_ context.Context, key []byte) (*merkletree.Node, error) {
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
func (m *Storage) GetRoot(_ context.Context) (*merkletree.Hash, error) {
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
