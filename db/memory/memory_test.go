package memory

import (
	"github.com/iden3/go-merkletree-sql"
	"testing"

	"github.com/iden3/go-merkletree-sql/db/test"
	"github.com/stretchr/testify/require"
)

func TestMemoryStorageInterface(t *testing.T) {
	var db merkletree.Storage //nolint:gosimple

	db = NewMemoryStorage()
	require.NotNil(t, db)
}

type MemoryStorageBuilder struct{}

func (builder *MemoryStorageBuilder) NewStorage(t *testing.T) merkletree.Storage {
	return NewMemoryStorage()
}

func TestAll(t *testing.T) {
	builder := &MemoryStorageBuilder{}
	test.TestAll(t, builder)
}
