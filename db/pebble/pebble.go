package pebble

import (
	"bytes"
	"encoding/json"

	"github.com/cockroachdb/pebble"
	"github.com/iden3/go-merkletree/db"
	log "github.com/sirupsen/logrus"
)

// PebbleStorage implements the db.Storage interface
type PebbleStorage struct {
	pdb    *pebble.DB
	prefix []byte
}

// PebbleStorageTx implements the db.Tx interface
type PebbleStorageTx struct {
	// FUTURE currently Tx is using the same strategy than in MemoryDB and
	// LevelDB, in next iteration can be moved to Pebble Batch strategy
	*PebbleStorage
	cache db.KvMap
}

// NewPebbleStorage returns a new PebbleStorage
func NewPebbleStorage(path string, errorIfMissing bool) (*PebbleStorage, error) {
	o := &pebble.Options{
		ErrorIfNotExists: errorIfMissing,
	}
	rdb, err := pebble.Open(path, o)
	if err != nil {
		return nil, err
	}
	return &PebbleStorage{rdb, []byte{}}, nil
}

type storageInfo struct {
	KeyCount   int
	ClaimCount int
}

// Info implements the method Info of the interface db.Storage
func (p *PebbleStorage) Info() string {
	keycount := 0
	claimcount := 0
	err := p.Iterate(func(key []byte, value []byte) (bool, error) {
		if value[0] == byte(1) {
			claimcount++
		}

		keycount++
		return true, nil
	})
	if err != nil {
		return err.Error()
	}
	json, _ := json.MarshalIndent(
		storageInfo{
			KeyCount:   keycount,
			ClaimCount: claimcount,
		},
		"", "  ",
	)
	return string(json)
}

// WithPrefix implements the method WithPrefix of the interface db.Storage
func (p *PebbleStorage) WithPrefix(prefix []byte) db.Storage {
	return &PebbleStorage{p.pdb, db.Concat(p.prefix, prefix)}
}

// NewTx implements the method NewTx of the interface db.Storage
func (p *PebbleStorage) NewTx() (db.Tx, error) {
	return &PebbleStorageTx{p, make(db.KvMap)}, nil
}

// Get retreives a value from a key in the db.Storage
func (p *PebbleStorage) Get(key []byte) ([]byte, error) {
	v, closer, err := p.pdb.Get(db.Concat(p.prefix, key[:]))
	if err == pebble.ErrNotFound {
		return nil, db.ErrNotFound
	}
	closer.Close()
	return v, err
}

// Iterate implements the method Iterate of the interface db.Storage
func (p *PebbleStorage) Iterate(f func([]byte, []byte) (bool, error)) error {
	// NewIter already provides a point-in-time view of the current DB
	// state, but if is used for long term (is not the case), should use an
	// iterator over an snapshot:
	// snapshot := p.pdb.NewSnapshot()
	// defer snapshot.Close()
	// iter := snapshot.NewIter(nil)
	iter := p.pdb.NewIter(nil)
	defer iter.Close()

	iter.First() // move the iterator to the first key/value pair
	if len(iter.Key()) < len(p.prefix) || !bytes.Equal(iter.Key()[:len(p.prefix)], p.prefix) {
	} else {
		localKey := iter.Key()[len(p.prefix):]
		if _, err := f(localKey, iter.Value()); err != nil {
			return err
		}
	}
	for iter.Next() {
		if len(iter.Key()) < len(p.prefix) || !bytes.Equal(iter.Key()[:len(p.prefix)], p.prefix) {
			continue
		}
		localKey := iter.Key()[len(p.prefix):]
		if cont, err := f(localKey, iter.Value()); err != nil {
			return err
		} else if !cont {
			break
		}
	}
	return iter.Error()
}

// Get retreives a value from a key in the interface db.Tx
func (tx *PebbleStorageTx) Get(key []byte) ([]byte, error) {
	var err error

	fullkey := db.Concat(tx.prefix, key)

	if value, ok := tx.cache.Get(fullkey); ok {
		return value, nil
	}

	value, closer, err := tx.pdb.Get(fullkey)
	if err == pebble.ErrNotFound {
		return nil, db.ErrNotFound
	}
	closer.Close()

	return value, err
}

// Put saves a key:value into the db.Storage
func (tx *PebbleStorageTx) Put(k, v []byte) {
	tx.cache.Put(db.Concat(tx.prefix, k[:]), v)
}

// Add implements the method Add of the interface db.Tx
func (tx *PebbleStorageTx) Add(atx db.Tx) {
	ldbtx := atx.(*PebbleStorageTx)
	for _, v := range ldbtx.cache {
		tx.cache.Put(v.K, v.V)
	}
}

// Commit implements the method Commit of the interface db.Tx
func (tx *PebbleStorageTx) Commit() error {
	batch := tx.PebbleStorage.pdb.NewBatch()
	for _, v := range tx.cache {
		_ = batch.Set(v.K, v.V, nil)
	}

	tx.cache = nil
	return batch.Commit(nil)
}

// Close implements the method Close of the interface db.Tx
func (tx *PebbleStorageTx) Close() {
	tx.cache = nil
}

// Close implements the method Close of the interface db.Storage
func (p *PebbleStorage) Close() {
	if err := p.pdb.Close(); err != nil {
		panic(err)
	}
	log.Info("Database closed")
}

// Pebble is an extra method that returns the *pebble.DB
func (p *PebbleStorage) Pebble() *pebble.DB {
	return p.pdb
}

// List implements the method List of the interface db.Storage
func (p *PebbleStorage) List(limit int) ([]db.KV, error) {
	ret := []db.KV{}
	err := p.Iterate(func(key []byte, value []byte) (bool, error) {
		ret = append(ret, db.KV{K: db.Clone(key), V: db.Clone(value)})
		if len(ret) == limit {
			return false, nil
		}
		return true, nil
	})
	return ret, err
}
