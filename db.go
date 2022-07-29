package merkletree

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
)

// ErrNotFound is used by the implementations of the interface db.Storage for
// when a key is not found in the storage
var ErrNotFound = errors.New("key not found")

// Storage is the interface that defines the methods for the storage used in
// the merkletree. Examples of the interface implementation can be found at
// db/memory and db/leveldb directories.
type Storage interface {
	Get(context.Context, []byte) (*Node, error)
	Put(ctx context.Context, k []byte, v *Node) error
	GetRoot(context.Context) (*Hash, error)
	SetRoot(context.Context, *Hash) error
}

// KV contains a key (K) and a value (V)
type KV struct {
	K []byte
	V Node
}

// KvMap is a key-value map between a sha256 byte array hash, and a KV struct
type KvMap map[[sha256.Size]byte]KV

// Get retrieves the value respective to a key from the KvMap
func (m KvMap) Get(k []byte) (Node, bool) {
	v, ok := m[sha256.Sum256(k)]
	return v.V, ok
}

// Put stores a key and a value in the KvMap
func (m KvMap) Put(k []byte, v Node) {
	m[sha256.Sum256(k)] = KV{k, v}
}

// Concat concatenates arrays of bytes
func Concat(vs ...[]byte) []byte {
	var b bytes.Buffer
	for _, v := range vs {
		b.Write(v)
	}
	return b.Bytes()
}

// Clone clones a byte array into a new byte array
func Clone(b0 []byte) []byte {
	b1 := make([]byte, len(b0))
	copy(b1, b0)
	return b1
}
