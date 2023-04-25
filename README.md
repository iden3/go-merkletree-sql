# go-merkletree-sql [![GoDoc](https://godoc.org/github.com/iden3/go-merkletree-sql/v2?status.svg)](https://godoc.org/github.com/iden3/go-merkletree-sql/v2) [![Go Report Card](https://goreportcard.com/badge/github.com/iden3/go-merkletree-sql/v2)](https://goreportcard.com/report/github.com/iden3/go-merkletree-sql/v2) [![Test](https://github.com/iden3/go-merkletree-sql/v2/workflows/Test/badge.svg)](https://github.com/iden3/go-merkletree-sql/v2/actions?query=workflow%3ATest)

MerkleTree compatible with version from [circomlib](https://github.com/iden3/circomlib).

Adaptation of the merkletree from https://github.com/iden3/go-iden3-core/tree/v0.0.8 with several changes and more functionalities.

## Usage
More detailed examples can be found at the [tests](https://github.com/iden3/go-merkletree-sql/v2/blob/master/merkletree_test.go), and in the [documentation](https://godoc.org/github.com/iden3/go-merkletree-sql/v2).

```go
import (
	"context"
	"math/big"
	"testing"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	sql "github.com/iden3/go-merkletree-sql/v2/db/pgx"
	"github.com/stretchr/testify/require"
)

func TestMT(t *testing.T) {
	mtDepth := 40     // maximum depth of the tree
	mtId := uint64(1) // id of tree in sql database, you can have multiple trees with different ids
	ctx := context.Background()

	var treeStorage merkletree.Storage

	// setup pgxConn here
	treeStorage = sql.NewSqlStorage(pgxConn, mtId)
	// OR
	treeStorage = memory.NewMemoryStorage()

	mt, err := merkletree.NewMerkleTree(ctx, treeStorage, mtDepth)
	require.NoError(t, err)

	err = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	require.NoError(t, err)

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(1), mt.Root())
	require.NoError(t, err)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(1), big.NewInt(2))
	require.True(t, valid)
}
```

## Contributing

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as below, without any additional terms or conditions.

## License

Copyright 2023 0kims Association

This project is licensed under either of

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))
- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))

at your option.
