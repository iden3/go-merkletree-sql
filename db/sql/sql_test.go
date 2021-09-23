package sql

import (
	"errors"
	"fmt"
	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/test"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"os"
	"strconv"
	"testing"
)

var maxMTId uint64 = 0
var cleared = false

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
	//if !cleared {
	dbx.Exec("TRUNCATE TABLE mt_roots")
	dbx.Exec("TRUNCATE TABLE mt_nodes")
	cleared = true
	//}

	return dbx, nil
}

type SqlStorageBuilder struct{}

func (builder *SqlStorageBuilder) NewStorage(t *testing.T) merkletree.Storage {

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
	//sto := sqlStorage(t)
	builder := &SqlStorageBuilder{}

	test.TestAll(t, builder)
}
