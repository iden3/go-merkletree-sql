package circom

import (
	"context"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/iden3/go-merkletree-sql/v3"
	"github.com/iden3/go-merkletree-sql/v3/db/memory"
	"github.com/stretchr/testify/require"
)

func TestSmtVerifier(t *testing.T) {
	storage := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, storage, 4)
	require.Nil(t, err)

	_, err = mt.Add(ctx, big.NewInt(1), big.NewInt(11))
	require.Nil(t, err)

	cvp, err := GenerateSCVerifierProof(ctx, big.NewInt(1), nil, mt)
	require.Nil(t, err)
	jCvp, err := json.Marshal(cvp)
	require.Nil(t, err)
	// expect siblings to be '[]', instead of 'null'
	expected := `{"root":"6525056641794203554583616941316772618766382307684970171204065038799368146416","siblings":[],"oldKey":"0","oldValue":"0","isOld0":false,"key":"1","value":"11","fnc":0}` //nolint:lll

	require.Equal(t, expected, string(jCvp))
	_, err = mt.Add(ctx, big.NewInt(2), big.NewInt(22))
	require.Nil(t, err)
	_, err = mt.Add(ctx, big.NewInt(3), big.NewInt(33))
	require.Nil(t, err)
	_, err = mt.Add(ctx, big.NewInt(4), big.NewInt(44))
	require.Nil(t, err)

	cvp, err = GenerateCircomVerifierProof(ctx, big.NewInt(2), nil, mt)
	require.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	require.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Expect siblings with the extra 0 that the circom circuits need
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700","0","0","0"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	require.Equal(t, expected, string(jCvp))

	cvp, err = GenerateSCVerifierProof(ctx, big.NewInt(2), nil, mt)
	require.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	require.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Without the extra 0 that the circom circuits need, but that are not
	// needed at a smart contract verification
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	require.Equal(t, expected, string(jCvp))
}

type node struct {
	k *big.Int
	v *big.Int
}

func TestGenerateSCVerifierProof_Success(t *testing.T) {
	tests := []struct {
		name      string
		nodes     []node
		searchKey *big.Int
		expected  *CircomVerifierProof
	}{
		{
			name:      "Proof for EXISTS node. ONE node on tree",
			searchKey: big.NewInt(1),
			nodes: []node{
				{
					k: big.NewInt(1),
					v: big.NewInt(2),
				},
			},
			expected: &CircomVerifierProof{
				Root:     requireLeafKey(big.NewInt(1), big.NewInt(2)),
				Siblings: []*merkletree.Hash{},
				OldKey:   &merkletree.HashZero,
				OldValue: &merkletree.HashZero,
				IsOld0:   false,
				Key:      requireSingleHash(big.NewInt(1)),
				Value:    requireSingleHash(big.NewInt(2)),
				Fnc:      0,
			},
		},
		{
			name:      "Proof of EXISTS node. NOT EMPTY tree",
			searchKey: big.NewInt(2), // 10
			nodes: []node{
				{
					k: big.NewInt(1), // 01
					v: big.NewInt(1),
				},
				{
					k: big.NewInt(2), // 10
					v: big.NewInt(2),
				},
			},
			expected: &CircomVerifierProof{
				Root: requireHash(
					requireLeafKey(big.NewInt(2), big.NewInt(2)).BigInt(), // go to left
					requireLeafKey(big.NewInt(1), big.NewInt(1)).BigInt(), // go to right
				),
				Siblings: []*merkletree.Hash{
					requireLeafKey(big.NewInt(1), big.NewInt(1)),
				},
				OldKey:   &merkletree.HashZero,
				OldValue: &merkletree.HashZero,
				IsOld0:   false,
				Key:      requireSingleHash(big.NewInt(2)),
				Value:    requireSingleHash(big.NewInt(2)),
				Fnc:      0,
			},
		},
		{
			name:      "Proof for NOT EXISTS node. ONE node on tree",
			searchKey: big.NewInt(3), // 11
			nodes: []node{
				{
					k: big.NewInt(1), // 01
					v: big.NewInt(1),
				},
			},
			expected: &CircomVerifierProof{
				Root:     requireLeafKey(big.NewInt(1), big.NewInt(1)),
				Siblings: []*merkletree.Hash{},
				OldKey:   requireSingleHash(big.NewInt(1)),
				OldValue: requireSingleHash(big.NewInt(1)),
				IsOld0:   false,
				Key:      requireSingleHash(big.NewInt(3)),
				Value:    requireSingleHash(big.NewInt(1)),
				Fnc:      1,
			},
		},
		{
			name:      "Proof for NOT EXISTS node. NOT EMPTY tree",
			searchKey: big.NewInt(3), // 11
			nodes: []node{
				{
					k: big.NewInt(1), // 01
					v: big.NewInt(1),
				},
				{
					k: big.NewInt(2), // 10
					v: big.NewInt(2),
				},
			},
			expected: &CircomVerifierProof{
				Root: requireHash(
					requireLeafKey(big.NewInt(2), big.NewInt(2)).BigInt(), // go to left
					requireLeafKey(big.NewInt(1), big.NewInt(1)).BigInt(), // go to right
				),
				Siblings: []*merkletree.Hash{
					requireLeafKey(big.NewInt(2), big.NewInt(2)),
				},
				OldKey:   requireSingleHash(big.NewInt(1)),
				OldValue: requireSingleHash(big.NewInt(1)),
				IsOld0:   false,
				Key:      requireSingleHash(big.NewInt(3)),
				Value:    requireSingleHash(big.NewInt(1)),
				Fnc:      1,
			},
		},
		{
			name:      "Proof for NOT EXISTS node. EMPTY tree",
			searchKey: big.NewInt(3), // 11
			nodes:     []node{},
			expected: &CircomVerifierProof{
				Root:     &merkletree.HashZero,
				Siblings: []*merkletree.Hash{},
				OldKey:   &merkletree.HashZero,
				OldValue: &merkletree.HashZero,
				IsOld0:   true,
				Key:      requireSingleHash(big.NewInt(3)),
				Value:    &merkletree.HashZero,
				Fnc:      1,
			},
		},
		{
			name:      "Proof for NOT EXISTS node. Case with empty node",
			searchKey: big.NewInt(5), // 11
			nodes: []node{
				{
					k: big.NewInt(2), // 010
					v: big.NewInt(2), // 010
				},
				{
					k: big.NewInt(3), // 011
					v: big.NewInt(3), // 011
				},
				{
					k: big.NewInt(7), // 111
					v: big.NewInt(7), // 111
				},
			},
			expected: &CircomVerifierProof{
				Root: func() *merkletree.Hash {
					botR := requireHash(
						requireLeafKey(big.NewInt(3), big.NewInt(3)).BigInt(),
						requireLeafKey(big.NewInt(7), big.NewInt(7)).BigInt(),
					).BigInt()

					topBotR := requireHash(
						merkletree.HashZero.BigInt(),
						botR,
					).BigInt()

					root := requireHash(
						requireLeafKey(big.NewInt(2), big.NewInt(2)).BigInt(),
						topBotR,
					)

					return root
				}(),
				Siblings: []*merkletree.Hash{
					requireLeafKey(big.NewInt(2), big.NewInt(2)),
					func() *merkletree.Hash {
						botR := requireHash(
							requireLeafKey(big.NewInt(3), big.NewInt(3)).BigInt(),
							requireLeafKey(big.NewInt(7), big.NewInt(7)).BigInt(),
						)
						return botR
					}(),
				},
				OldKey:   &merkletree.HashZero,
				OldValue: &merkletree.HashZero,
				IsOld0:   true,
				Key:      requireSingleHash(big.NewInt(5)),
				Value:    &merkletree.HashZero,
				Fnc:      1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := memory.NewMemoryStorage()
			mt, err := merkletree.NewMerkleTree(context.Background(), db, 10)
			require.NoError(t, err)

			for _, n := range tt.nodes {
				_, err := mt.Add(context.Background(), n.k, n.v)
				require.NoError(t, err)
			}

			circomProof, err := GenerateSCVerifierProof(context.Background(), tt.searchKey, nil, mt)
			require.NoError(t, err)
			// debugEqual(t, tt.expected, circomProof)
			require.Equal(t, tt.expected, circomProof)
		})
	}
}

// since stretchr/testify unsupported print value by pointer.
// You can use debug for more information.
// https://github.com/stretchr/testify/pull/1287
//
//nolint:unused // Uses for debug
func debugEqual(t *testing.T, expected, actual *CircomVerifierProof) {
	require.Equal(t, expected.Root, actual.Root)

	require.Len(t, actual.Siblings, len(expected.Siblings))
	for i := range expected.Siblings {
		require.Equal(t, expected.Siblings[i], actual.Siblings[i], "incorrect sibling position: %d", i)
	}

	require.Equal(t, expected.OldKey, actual.OldKey, "old key")
	require.Equal(t, expected.OldValue, actual.OldValue, "old value")
	require.Equal(t, expected.IsOld0, actual.IsOld0, "is old 0")
	require.Equal(t, expected.Key, actual.Key, "new key")
	require.Equal(t, expected.Value, actual.Value, "new value")
	require.Equal(t, expected.Fnc, actual.Fnc, "fun")
}

func requireLeafKey(k *big.Int, v *big.Int) *merkletree.Hash {
	h, err := merkletree.LeafKey(requireSingleHash(k), requireSingleHash(v))
	if err != nil {
		panic(err)
	}
	return h
}

func requireSingleHash(hash *big.Int) *merkletree.Hash {
	h, err := merkletree.NewHashFromBigInt(hash)
	if err != nil {
		panic(err)
	}
	return h
}

func requireHash(hash ...*big.Int) *merkletree.Hash {
	h, err := merkletree.HashElems(hash...)
	if err != nil {
		panic(err)
	}
	return h
}
