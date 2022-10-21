# Unit test
test:
	go test -v -race -timeout=60s ./...

# Linter
lint:
	 golangci-lint --config .golangci.yml run