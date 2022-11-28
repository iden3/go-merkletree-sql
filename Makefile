SHELL := /bin/bash

# There is no easy way to run the linter and tests for submodules.
# The following cases do not work.
# go test ./db/pgx/... || go test ./db/pgx/. || etc.
# golangci-lint --config .golangci.yml run db/pgx/*.go || golangci-lint --config .golangci.yml run db/pgx/* || etc.

test:
	$(eval SUB_DIRS:=$(shell find . -type f -name go.mod -printf '%h\n'))
	for dir in ${SUB_DIRS} ; do \
		cd ${PWD}/$$dir && go test -race -count=1 -timeout=60s ./... ; \
	done

.SILENT:
lint:
	$(eval SUB_DIRS:=$(shell find . -type f -name go.mod -printf '%h\n'))
	for dir in ${SUB_DIRS} ; do \
		cd ${PWD}/$$dir && golangci-lint --config ${PWD}/.golangci.yml run ; \
	done
