# Unit test
test:
	go test -v -race -timeout=60s -count=1 ./...

# Linter
lint:
	 golangci-lint --config .golangci.yml run

# Fix linter
fix-lint:
	golangci-lint --config .golangci.yml run --fix
