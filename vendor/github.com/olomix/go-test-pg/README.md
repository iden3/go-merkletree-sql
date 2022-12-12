# go-test-pg — Helper tool to test go programs with PostgreSQL database

[![GoDoc](https://godoc.org/github.com/olomix/go-test-pg?status.svg)](https://godoc.org/github.com/olomix/go-test-pg)

The aim this package is to help test golang programs against PostgreSQL
database. It creates an empty database for each test and drops it when test
is complete.

As a side effect tool checks that all resources are released when test exits.
If any Rows is not closed or Conn is not released to pool, test fails.

`go-test-pg` uses schema file to initialize database with. It creates
template database with this schema. Then each temporary database for every test
creates from this template database. If the template database for this
schema is exists, it will be reused. The name of the template database 
is composed of `baseName` and md5 hashsum of schema file content. If schema file
is empty, then use default PostgreSQL empty database `template1`.

On complete, temporary databases would be dropped, template database will not
be dropped and would remain for future reuse.

Template database would be created only on first use. If you call `NewPool`
and do not call `With<something>` on it, real database would not be touched.

Each method was `Std` version that returns `*sql.DB`. For example,
default method `WithFixtures` returns `*pgxpool.Pool` and `WithStdFixtures`
returns `*sql.DB`.

## Example usage

```go
package main

import (
	"context"
	"testing"

	ptg "github.com/olomix/go-test-pg"
)

var dbpool = &ptg.Pgpool{SchemaFile: "../schema.sql"}

func TestX(t *testing.T) {
    dbPool := dbpool.WithEmpty(t)
    var dbName string
    err := dbPool.
        QueryRow(context.Background(), "SELECT current_database()").
        Scan(&dbName)
    if err != nil {
        t.Fatal(err)
    }

    t.Log(dbName)
}
```

Connection to database configured using standard PostgreSQL environment
variable https://www.postgresql.org/docs/11/libpq-envars.html. User needs
permissions to create databases.

If you want to skip all database tests, you need to set `Skip` field in Pgpool
struct to `true`.

```go
var dbpool = &ptg.Pgpool{Skip: true}
```
