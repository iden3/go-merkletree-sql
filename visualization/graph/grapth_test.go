package graph_test

import (
	"bytes"
	"context"
	"math/big"
	"strconv"
	"testing"

	"github.com/iden3/go-merkletree-sql/v2"
	db "github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-merkletree-sql/visualization/graph"
	"github.com/stretchr/testify/require"
)

func TestPrintGraphViz(t *testing.T) {
	store := db.NewMemoryStorage()
	mt, err := merkletree.NewMerkleTree(context.Background(), store, 3)
	require.NoError(t, err)

	err = mt.Add(context.Background(), big.NewInt(1), big.NewInt(1))
	require.NoError(t, err)
	err = mt.Add(context.Background(), big.NewInt(2), big.NewInt(1))
	require.NoError(t, err)
	err = mt.Add(context.Background(), big.NewInt(3), big.NewInt(1))
	require.NoError(t, err)
	err = mt.Add(context.Background(), big.NewInt(4), big.NewInt(1))
	require.NoError(t, err)

	err = graph.PrintGraphViz(context.Background(), mt.Root(), mt)
	require.NoError(t, err)
}

func TestGraphViz(t *testing.T) {
	tests := []struct {
		keys     []*big.Int
		expected string
	}{
		{
			keys: []*big.Int{
				big.NewInt(1),
				big.NewInt(2),
			},
			expected: `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
"92200807..." -> {"44133088..." "12439047..."}
"44133088..." [style=filled];
"12439047..." [style=filled];
}
`,
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			store := db.NewMemoryStorage()
			mt, err := merkletree.NewMerkleTree(context.Background(), store, 3)
			require.NoError(t, err)

			for _, k := range tt.keys {
				err = mt.Add(context.Background(), k, big.NewInt(1))
				require.NoError(t, err)
			}

			got := bytes.NewBufferString("")
			err = graph.GraphViz(context.Background(), got, mt.Root(), mt)
			require.NoError(t, err)
			require.Equal(t, tt.expected, got.String())
		})
	}
}
