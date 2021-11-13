package sql

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/test"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	go_test_pg "github.com/olomix/go-test-pg"
	"github.com/stretchr/testify/require"
)

var maxMTId uint64 = 0
var cleared = false

var dbPool = go_test_pg.Pgpool{
	BaseName:   "merkletree_sql",
	SchemaFile: "./schema.sql",
	Skip:       false,
}
func setupDB2(t *testing.T) (*sqlx.DB, error) {
	db := dbPool.WithStdEmpty(t)
	return sqlx.NewDb(db, "pgx"), nil
}

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
	dbUser := os.Getenv("PGUSER")
	if dbUser == "" {
		osUser, err := user.Current()
		if err != nil {
			return nil, err
		}
		dbUser = osUser.Username
	}
	password := os.Getenv("PGPASSWORD")
	//if password == "" {
	//	return nil, errors.New("No PGPASSWORD envvar specified")
	//}
	dbname := os.Getenv("PGDATABASE")
	if dbname == "" {
		dbname = "test"
	}

	psqlconn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host,
		port,
		dbUser,
		password,
		dbname,
	)
	dbx, err := sqlx.Connect("postgres", psqlconn)
	if err != nil {
		return nil, err
	}

	// clear MerkleTree table
	//if !cleared {
	dbx.Exec("TRUNCATE TABLE mt_roots")
	dbx.Exec("TRUNCATE TABLE mt_nodes")
	cleared = true
	//}

	return dbx, nil
}

type SqlStorageBuilder struct{}

func (builder *SqlStorageBuilder) NewStorage(t *testing.T) merkletree.Storage {

	dbx, err := setupDB2(t)
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

	return sto
}

func TestSql(t *testing.T) {
	//sto := sqlStorage(t)
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