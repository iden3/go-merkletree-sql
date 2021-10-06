package sql

import (
	"errors"
	"fmt"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/test"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"os"
	"strconv"
	"sync"
	"testing"
)

var maxMTId uint64 = 0
var cleared = false
var m sync.Mutex

func setupDB() (*sqlx.DB, error) {
	var err error
	host := os.Getenv("PGHOST")
	if host == "" {
		host = "localhost"
	}
	port, _ := strconv.Atoi(os.Getenv("PGPORT"))
	if port == 0 {
		port = 5432
	}
	user := os.Getenv("PGUSER")
	if user == "" {
		user = "user"
	}
	password := os.Getenv("PGPASSWORD")
	if password == "" {
		return nil, errors.New("No PGPASSWORD envvar specified")
	}
	dbname := os.Getenv("PGDATABASE")
	if dbname == "" {
		dbname = "test"
	}

	psqlconn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host,
		port,
		user,
		password,
		dbname,
	)
	dbx, err := sqlx.Connect("postgres", psqlconn)
	if err != nil {
		return nil, err
	}

	// clear MerkleTree table
	if !cleared {
		dbx.Exec("TRUNCATE TABLE mt_roots")
		dbx.Exec("TRUNCATE TABLE mt_nodes")
		cleared = true
	}

	return dbx, nil
}

type SqlStorageBuilder struct{}

func (builder *SqlStorageBuilder) NewStorage(t *testing.T) merkletree.Storage {

	m.Lock()
	defer m.Unlock()

	dbx, err := setupDB()
	if err != nil {
		t.Fatal(err)
		return nil
	}

	sto, err := NewSqlStorage(dbx, maxMTId)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	maxMTId++

	t.Cleanup(func() {
	})

	return sto
}

func TestSql(t *testing.T) {
	builder := &SqlStorageBuilder{}
	test.TestAll(t, builder, true)
}

func TestStorageWithVersions(t *testing.T) {

	builder := &SqlStorageBuilder{}

	stoTmp1 := builder.NewStorage(t)
	sto1, ok := stoTmp1.(*Storage)
	require.True(t, ok)
	defer sto1.Close()

	stoTmp2 := builder.NewStorage(t)
	sto2, ok := stoTmp2.(*Storage)
	require.True(t, ok)
	defer sto2.Close()

	var version uint64 = 1
	sto1.SetCurrentVersion(version)
	version++

	mt1, err := merkletree.NewMerkleTree(sto1, 140)
	require.Nil(t, err)
	defer mt1.DB().Close()
	mt2, err := merkletree.NewMerkleTree(sto2, 140)
	require.Nil(t, err)
	defer mt2.DB().Close()

	err = mt1.Add(big.NewInt(1), big.NewInt(119))
	assert.Nil(t, err)
	err = mt1.Add(big.NewInt(2), big.NewInt(229))
	assert.Nil(t, err)
	err = mt1.Add(big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	sto1.SetCurrentVersion(version)
	version++

	err = mt2.Add(big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	err = mt2.Add(big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	err = mt2.Add(big.NewInt(9876), big.NewInt(10))
	assert.Nil(t, err)

	sto1.SetCurrentVersion(version)
	version++

	_, err = mt1.Update(big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)
	_, err = mt1.Update(big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	_, err = mt2.Update(big.NewInt(9876), big.NewInt(6789))
	assert.Nil(t, err)

	sto1.SetCurrentVersion(version)
	version++

	assert.Equal(t, mt1.Root(), mt2.Root())
}
