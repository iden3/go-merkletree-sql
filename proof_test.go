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

	assert.Equal(t, proof.AllSiblings(), p.AllSiblings())
	assert.Equal(t, proof.NodeAux, p.NodeAux)
	assert.Equal(t, proof.Existence, p.Existence)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(1), big.NewInt(2))
	assert.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(1), big.NewInt(2))
	assert.True(t, valid)
}

func TestProof_MarshalJSON_NonInclusionProofWithoutNodeAux(t *testing.T) {
	db := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, db, 40)
	require.NoError(t, err)

	mt.Add(ctx, big.NewInt(1), big.NewInt(2))  //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(2), big.NewInt(8))  //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(3), big.NewInt(8))  //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(17), big.NewInt(8)) //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(18), big.NewInt(8)) //nolint:errcheck,gosec
	mt.Add(ctx, big.NewInt(19), big.NewInt(8)) //nolint:errcheck,gosec

	expected := `{"existence":false,"siblings":["11445591970430686524669302036672429838422356071483318076578901368167305782934","0","19623034175990655567331847335376057032468128626960956120127301863642129702078"]}` //nolint:lll

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(6), mt.Root())
	require.NoError(t, err)
	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(14), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(22), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(30), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(38), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	// gives the same proof
	proof, _, err = mt.GenerateProof(ctx, big.NewInt(46), mt.Root())
	require.NoError(t, err)
	jsonProof, err = proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	//fmt.Println(string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	assert.Equal(t, proof.AllSiblings(), p.AllSiblings())
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

	mt.Add(ctx, big.NewInt(1), big.NewInt(2)) //nolint:errcheck,gosec // 1 0b000001
	mt.Add(ctx, big.NewInt(3), big.NewInt(8)) //nolint:errcheck,gosec // 3 0b000011
	mt.Add(ctx, big.NewInt(7), big.NewInt(8)) //nolint:errcheck,gosec // 7 0b000111
	mt.Add(ctx, big.NewInt(9), big.NewInt(8)) //nolint:errcheck,gosec // 9 0b001001

	//nolint:lll
	expected := `{"existence":false,"siblings":["0","12166698708103333637493481507263348370172773813051235807348785759284762677336","7750564177398573185975752951631372712868228752107043582052272719841058100111"],"node_aux":{"key":"3","value":"8"}}`

	proof, _, err := mt.GenerateProof(ctx, big.NewInt(11), mt.Root()) // 11 0b001011
	require.NoError(t, err)
	jsonProof, err := proof.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof))

	//fmt.Println(string(jsonProof))

	jsonProof2, err := json.Marshal(proof)
	require.NoError(t, err)
	assert.Equal(t, expected, string(jsonProof2))

	var p merkletree.Proof
	err = json.Unmarshal(jsonProof, &p)
	require.NoError(t, err)

	assert.Equal(t, proof.AllSiblings(), p.AllSiblings())
	assert.Equal(t, proof.NodeAux, p.NodeAux)
	assert.Equal(t, proof.Existence, p.Existence)

	valid := merkletree.VerifyProof(mt.Root(), proof, big.NewInt(11), big.NewInt(0))
	assert.True(t, valid)

	valid = merkletree.VerifyProof(mt.Root(), &p, big.NewInt(11), big.NewInt(0))
	assert.True(t, valid)
}
