package merkletree_test

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-merkletree-sql"
	"github.com/iden3/go-merkletree-sql/db/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProof_MarshalJSON(t *testing.T) {
	db := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, db, 40)
	require.NoError(t, err)

	mt.Add(ctx, big.NewInt(0x0001), big.NewInt(2)) //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(0x0011), big.NewInt(8)) //nolint:errcheck,gosec
	proof, _, err := mt.GenerateProof(ctx, big.NewInt(1), mt.Root())
	require.NoError(t, err)

	expected := `{"existence":true,"siblings":["0","0","0","0","13167809686468103484252970188077542812117386492167015186848701688893624465068"]}` //nolint:lll

	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	assert.Equal(t, proof.Siblings, p.Siblings)
	assert.Equal(t, proof.AllSiblings(), p.AllSiblings())
	assert.Equal(t, proof.NodeAux, p.NodeAux)
	assert.Equal(t, proof.Depth(), p.Depth())
	assert.Equal(t, proof.NotEmpties(), p.NotEmpties())

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(1), big.NewInt(2))
	assert.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(1), big.NewInt(2))
	assert.True(t, valid)
}
