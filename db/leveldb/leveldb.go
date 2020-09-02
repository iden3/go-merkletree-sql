package leveldb

import (
	"encoding/json"

	"github.com/iden3/go-merkletree/db"
	log "github.com/sirupsen/logrus"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// LevelDbStorage implements the db.Storage interface
type LevelDbStorage struct {
	ldb    *leveldb.DB
	prefix []byte
}

// LevelDbStorageTx implements the db.Tx interface
type LevelDbStorageTx struct {
	*LevelDbStorage
	cache db.KvMap
}

// NewLevelDbStorage returns a new LevelDbStorage
func NewLevelDbStorage(path string, errorIfMissing bool) (*LevelDbStorage, error) {
	o := &opt.Options{
		ErrorIfMissing: errorIfMissing,
	}
	ldb, err := leveldb.OpenFile(path, o)
	if err != nil {
		return nil, err
	}
	return &LevelDbStorage{ldb, []byte{}}, nil
}

type storageInfo struct {
	KeyCount   int
	ClaimCount int
}

// Info implements the method Info of the interface db.Storage
func (l *LevelDbStorage) Info() string {
	snapshot, err := l.ldb.GetSnapshot()
	if err != nil {
		return err.Error()
	}

	keycount := 0
	claimcount := 0
	iter := snapshot.NewIterator(nil, nil)
	for iter.Next() {
		if iter.Value()[0] == byte(1) {
			claimcount++
		}

		keycount++
	}
	iter.Release()
	if err := iter.Error(); err != nil {
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
func (l *LevelDbStorage) WithPrefix(prefix []byte) db.Storage {
	return &LevelDbStorage{l.ldb, db.Concat(l.prefix, prefix)}
}

// NewTx implements the method NewTx of the interface db.Storage
func (l *LevelDbStorage) NewTx() (db.Tx, error) {
	return &LevelDbStorageTx{l, make(db.KvMap)}, nil
}

// Get retreives a value from a key in the db.Storage
func (l *LevelDbStorage) Get(key []byte) ([]byte, error) {
	v, err := l.ldb.Get(db.Concat(l.prefix, key[:]), nil)
	if err == errors.ErrNotFound {
		return nil, db.ErrNotFound
	}
	return v, err
}

// Iterate implements the method Iterate of the interface db.Storage
func (l *LevelDbStorage) Iterate(f func([]byte, []byte) (bool, error)) error {
	// FIXME: Use the prefix!
	snapshot, err := l.ldb.GetSnapshot()
	if err != nil {
		return err
	}
	iter := snapshot.NewIterator(util.BytesPrefix(l.prefix), nil)
	defer iter.Release()
	for iter.Next() {
		localKey := iter.Key()[len(l.prefix):]
		if cont, err := f(localKey, iter.Value()); err != nil {
			return err
		} else if !cont {
			break
		}
	}
	iter.Release()
	return iter.Error()
}

// Get retreives a value from a key in the interface db.Tx
func (tx *LevelDbStorageTx) Get(key []byte) ([]byte, error) {
	var err error

	fullkey := db.Concat(tx.prefix, key)

	if value, ok := tx.cache.Get(fullkey); ok {
		return value, nil
	}

	value, err := tx.ldb.Get(fullkey, nil)
	if err == errors.ErrNotFound {
		return nil, db.ErrNotFound
	}

	return value, err
}

// Put saves a key:value into the db.Storage
func (tx *LevelDbStorageTx) Put(k, v []byte) error {
	tx.cache.Put(db.Concat(tx.prefix, k[:]), v)
	return nil
}

// Add implements the method Add of the interface db.Tx
func (tx *LevelDbStorageTx) Add(atx db.Tx) error {
	ldbtx := atx.(*LevelDbStorageTx)
	for _, v := range ldbtx.cache {
		tx.cache.Put(v.K, v.V)
	}
	return nil
}

// Commit implements the method Commit of the interface db.Tx
func (tx *LevelDbStorageTx) Commit() error {
	var batch leveldb.Batch
	for _, v := range tx.cache {
		batch.Put(v.K, v.V)
	}

	tx.cache = nil
	return tx.ldb.Write(&batch, nil)
}

// Close implements the method Close of the interface db.Tx
func (tx *LevelDbStorageTx) Close() {
	tx.cache = nil
}

// Close implements the method Close of the interface db.Storage
func (l *LevelDbStorage) Close() {
	if err := l.ldb.Close(); err != nil {
		panic(err)
	}
	log.Info("Database closed")
}

// LevelDB is an extra method that returns the *leveldb.DB
func (l *LevelDbStorage) LevelDB() *leveldb.DB {
	return l.ldb
}

// List implements the method List of the interface db.Storage
func (l *LevelDbStorage) List(limit int) ([]db.KV, error) {
	ret := []db.KV{}
	err := l.Iterate(func(key []byte, value []byte) (bool, error) {
		ret = append(ret, db.KV{K: db.Clone(key), V: db.Clone(value)})
		if len(ret) == limit {
			return false, nil
		}
		return true, nil
	})
	return ret, err
}
