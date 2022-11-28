package dump

import (
	"context"
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-merkletree-sql/v3"
	"github.com/iden3/go-merkletree-sql/v3/db/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDumpLeafsImportLeafs(t *testing.T) {
	ctx := context.Background()
	store1 := memory.NewMemoryStorage()
	store2 := memory.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(ctx, store1, 140)
	require.Nil(t, err)

	q1 := new(big.Int).Sub(constants.Q, big.NewInt(1))
	for i := 0; i < 10; i++ {
		// use numbers near under Q
		k := new(big.Int).Sub(q1, big.NewInt(int64(i)))
		v := big.NewInt(0)
		_, err = mt.Add(ctx, k, v)
		require.Nil(t, err)

		// use numbers near above 0
		k = big.NewInt(int64(i))
		_, err = mt.Add(ctx, k, v)
		require.Nil(t, err)
	}

	d, err := DumpLeafs(ctx, nil, mt)
	assert.Nil(t, err)

	mt2, err := merkletree.NewMerkleTree(ctx, store2, 140)
	require.Nil(t, err)
	err = ImportDumpedLeafs(ctx, d, mt2)
	assert.Nil(t, err)

	assert.Equal(t, mt.Root(), mt2.Root())
}
