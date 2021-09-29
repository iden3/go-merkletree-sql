module github.com/iden3/go-merkletree-sql/db/sql

go 1.17

require (
	github.com/iden3/go-merkletree-sql v1.0.0-pre5
	github.com/jmoiron/sqlx v1.3.4
	github.com/lib/pq v1.2.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/iden3/go-iden3-crypto v0.0.6 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.6.1 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c // indirect
)

replace github.com/iden3/go-merkletree-sql => ../../
