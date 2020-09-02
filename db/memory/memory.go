package memory

import (
	"bytes"
	"sort"

	"github.com/iden3/go-merkletree/db"
)

// MemoryStorage implements the db.Storage interface
type MemoryStorage struct {
	prefix []byte
	kv     db.KvMap
}

// MemoryStorageTx implements the db.Tx interface
type MemoryStorageTx struct {
	s  *MemoryStorage
	kv db.KvMap
}

// NewMemoryStorage returns a new MemoryStorage
func NewMemoryStorage() *MemoryStorage {
	kvmap := make(db.KvMap)
	return &MemoryStorage{[]byte{}, kvmap}
}

// Info implements the method Info of the interface db.Storage
func (m *MemoryStorage) Info() string {
	return "in-memory"
}

// WithPrefix implements the method WithPrefix of the interface db.Storage
func (m *MemoryStorage) WithPrefix(prefix []byte) db.Storage {
	return &MemoryStorage{db.Concat(m.prefix, prefix), m.kv}
}

// NewTx implements the method NewTx of the interface db.Storage
func (m *MemoryStorage) NewTx() (db.Tx, error) {
	return &MemoryStorageTx{m, make(db.KvMap)}, nil
}

// Get retreives a value from a key in the db.Storage
func (m *MemoryStorage) Get(key []byte) ([]byte, error) {
	if v, ok := m.kv.Get(db.Concat(m.prefix, key[:])); ok {
		return v, nil
	}
	return nil, db.ErrNotFound
}

// Iterate implements the method Iterate of the interface db.Storage
func (m *MemoryStorage) Iterate(f func([]byte, []byte) (bool, error)) error {
	kvs := make([]db.KV, 0)
	for _, v := range m.kv {
		if len(v.K) < len(m.prefix) || !bytes.Equal(v.K[:len(m.prefix)], m.prefix) {
			continue
		}
		localkey := v.K[len(m.prefix):]
		kvs = append(kvs, db.KV{K: localkey, V: v.V})
	}
	sort.SliceStable(kvs, func(i, j int) bool { return bytes.Compare(kvs[i].K, kvs[j].K) < 0 })

	for _, kv := range kvs {
		if cont, err := f(kv.K, kv.V); err != nil {
			return err
		} else if !cont {
			break
		}
	}
	return nil
}

// Get implements the method Get of the interface db.Tx
func (tx *MemoryStorageTx) Get(key []byte) ([]byte, error) {
	if v, ok := tx.kv.Get(db.Concat(tx.s.prefix, key)); ok {
		return v, nil
	}
	if v, ok := tx.s.kv.Get(db.Concat(tx.s.prefix, key)); ok {
		return v, nil
	}

	return nil, db.ErrNotFound
}

// Put implements the method Put of the interface db.Tx
func (tx *MemoryStorageTx) Put(k, v []byte) error {
	tx.kv.Put(db.Concat(tx.s.prefix, k), v)
	return nil
}

// Commit implements the method Commit of the interface db.Tx
func (tx *MemoryStorageTx) Commit() error {
	for _, v := range tx.kv {
		tx.s.kv.Put(v.K, v.V)
	}
	tx.kv = nil
	return nil
}

// Add implements the method Add of the interface db.Tx
func (tx *MemoryStorageTx) Add(atx db.Tx) error {
	mstx := atx.(*MemoryStorageTx)
	for _, v := range mstx.kv {
		tx.kv.Put(v.K, v.V)
	}
	return nil
}

// Close implements the method Close of the interface db.Tx
func (tx *MemoryStorageTx) Close() {
	tx.kv = nil
}

// Close implements the method Close of the interface db.Storage
func (m *MemoryStorage) Close() {
}

// List implements the method List of the interface db.Storage
func (m *MemoryStorage) List(limit int) ([]db.KV, error) {
	ret := []db.KV{}
	err := m.Iterate(func(key []byte, value []byte) (bool, error) {
		ret = append(ret, db.KV{K: db.Clone(key), V: db.Clone(value)})
		if len(ret) == limit {
			return false, nil
		}
		return true, nil
	})
	return ret, err
}
