package merkletree_test

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-merkletree-sql/v3"
	"github.com/iden3/go-merkletree-sql/v3/db/memory"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProof_MarshalJSON(t *testing.T) {
	db := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, db, 40)
	require.NoError(t, err)

	_, _ = mt.Add(ctx, big.NewInt(0b00001), big.NewInt(2)) // 1
	_, _ = mt.Add(ctx, big.NewInt(0b10001), big.NewInt(8)) // 17
	proof, _, err := mt.GenerateProof(ctx, big.NewInt(1), mt.Root())
	require.NoError(t, err)

	expected := "{\"existence\":true,\"" +
		"siblings\":[\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"acb6d2c171708d80a11b6480e2c88bb02b7299da248949acd34521cd56b71c1d\"]}" //nolint:lll

	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	require.JSONEq(t, expected, string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	require.JSONEq(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	require.Equal(t, proof.Siblings(), p.Siblings())
	require.Equal(t, proof.NodeAux, p.NodeAux)
	require.Equal(t, proof.Existence, p.Existence)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(1), big.NewInt(2))
	require.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(1), big.NewInt(2))
	require.True(t, valid)
}

func TestProof_MarshalJSON_NonInclusionProofWithoutNodeAux(t *testing.T) {
	db := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, db, 40)
	require.NoError(t, err)

	_, _ = mt.Add(ctx, big.NewInt(1), big.NewInt(2))
	_, _ = mt.Add(ctx, big.NewInt(2), big.NewInt(8))
	_, _ = mt.Add(ctx, big.NewInt(3), big.NewInt(8))
	_, _ = mt.Add(ctx, big.NewInt(17), big.NewInt(8))
	_, _ = mt.Add(ctx, big.NewInt(18), big.NewInt(8))
	_, _ = mt.Add(ctx, big.NewInt(19), big.NewInt(8))

	expected := "{\"existence\":false," +
		"\"siblings\":[\"9626630d48edcfcb934ce098e8223b5eedf4a19c019897b41c898c59b9f94d19\"," +
		"\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"be1c5b391e5ca5660f98e1ecfc68c908f85910b77ede0f79efa47a9b663e622b\"]}" //nolint:lll

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(6), mt.Root())
	require.NoError(t, err)
	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(14), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(22), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(30), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(38), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(46), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	assert.Equal(t, proof.Siblings(), p.Siblings())
	assert.Equal(t, proof.NodeAux, p.NodeAux)
	assert.Equal(t, proof.Existence, p.Existence)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(6), big.NewInt(0))
	assert.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(6), big.NewInt(0))
	assert.True(t, valid)
}

func TestProof_MarshalJSON_NonInclusionProofWithNodeAux(t *testing.T) {
	db := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, db, 40)
	require.NoError(t, err)

	_, _ = mt.Add(ctx, big.NewInt(1), big.NewInt(2)) // 1 0b000001
	_, _ = mt.Add(ctx, big.NewInt(3), big.NewInt(8)) // 3 0b000011
	_, _ = mt.Add(ctx, big.NewInt(7), big.NewInt(8)) // 7 0b000111
	_, _ = mt.Add(ctx, big.NewInt(9), big.NewInt(8)) // 9 0b001001

	//nolint:lll
	expected := "{\"existence\":false,\"siblings\":" +
		"[\"0000000000000000000000000000000000000000000000000000000000000000\"," +
		"\"58908ea0040f9fbf9411a90a60c0d7ca0d9e3b465c1fa5c80f1e0bd1801be61a\"," +
		"\"8f13884439a26f4295d310badce9fb6d2851fbf85de04de84fe3582ef3a92211\"]," +
		"\"node_aux\":{" +
		"\"key\":\"0300000000000000000000000000000000000000000000000000000000000000\"," +
		"\"value\":\"0800000000000000000000000000000000000000000000000000000000000000\"}}"

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(11), mt.Root()) // 11 0b001011
	require.NoError(t, err)
	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	assert.JSONEq(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	assert.Equal(t, proof.Siblings(), p.Siblings())
	assert.Equal(t, proof.NodeAux, p.NodeAux)
	assert.Equal(t, proof.Existence, p.Existence)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(11), big.NewInt(0))
	assert.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(11), big.NewInt(0))
	assert.True(t, valid)
}
