package sql

import (
	"errors"
	"io"
	"sync/atomic"
	"testing"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/test"
	go_test_pg "github.com/olomix/go-test-pg"
	"github.com/stretchr/testify/require"
)

var maxMTId uint64 = 0
var dbPool = go_test_pg.Pgpool{
	BaseName:   "merkletree_sql",
	SchemaFile: "./schema.sql",
	Skip:       false,
}

type SqlStorageBuilder struct{}

func (builder *SqlStorageBuilder) NewStorage(t *testing.T) merkletree.Storage {
	// Note: Use ENV vars to set database configuration.
	// See https://www.postgresql.org/docs/11/libpq-envars.html for details.
	db := dbPool.WithEmpty(t)

	mtId := atomic.AddUint64(&maxMTId, 1)

	return NewSqlStorage(db, mtId)
}

func TestSql(t *testing.T) {
	builder := &SqlStorageBuilder{}
	test.TestAll(t, builder)
}

func TestErrors(t *testing.T) {
	err := storageError{
		err: io.EOF,
		msg: "storage error",
	}
	require.EqualError(t, err, "storage error: EOF")
	require.Equal(t, io.EOF, errors.Unwrap(err))
}
