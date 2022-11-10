SHELL := /bin/bash

# Unit test
test:
	pushd $(shell pwd)/db/pgx && go test -race -count=1 -timeout=60s ./...
	pushd $(shell pwd)/db/sql && go test -race -count=1 -timeout=60s ./...
	go test -race -count=1 -timeout=60s ./...

# Linter
lint:
	 golangci-lint --config .golangci.yml run