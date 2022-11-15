package adapter

import (
	"context"
	"encoding/json"
	"github.com/iden3/go-merkletree-sql/v3"
	"github.com/iden3/go-merkletree-sql/v3/db/memory"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestSmtVerifier(t *testing.T) {
	storage := memory.NewMemoryStorage()
	ctx := context.Background()
	mt, err := merkletree.NewMerkleTree(ctx, storage, 4)
	assert.Nil(t, err)

	_, err = mt.Add(ctx, big.NewInt(1), big.NewInt(11))
	assert.Nil(t, err)

	cvp, err := GenerateSCVerifierProof(ctx, big.NewInt(1), nil, mt)
	assert.Nil(t, err)
	jCvp, err := json.Marshal(cvp)
	assert.Nil(t, err)
	// expect siblings to be '[]', instead of 'null'
	expected := `{"root":"6525056641794203554583616941316772618766382307684970171204065038799368146416","siblings":[],"oldKey":"0","oldValue":"0","isOld0":false,"key":"1","value":"11","fnc":0}` //nolint:lll

	assert.Equal(t, expected, string(jCvp))
	_, err = mt.Add(ctx, big.NewInt(2), big.NewInt(22))
	assert.Nil(t, err)
	_, err = mt.Add(ctx, big.NewInt(3), big.NewInt(33))
	assert.Nil(t, err)
	_, err = mt.Add(ctx, big.NewInt(4), big.NewInt(44))
	assert.Nil(t, err)

	cvp, err = GenerateCircomVerifierProof(ctx, big.NewInt(2), nil, mt)
	assert.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	assert.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Expect siblings with the extra 0 that the circom circuits need
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700","0","0","0"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	assert.Equal(t, expected, string(jCvp))

	cvp, err = GenerateSCVerifierProof(ctx, big.NewInt(2), nil, mt)
	assert.Nil(t, err)

	jCvp, err = json.Marshal(cvp)
	assert.Nil(t, err)
	// Test vectors generated using https://github.com/iden3/circomlib smt.js
	// Without the extra 0 that the circom circuits need, but that are not
	// needed at a smart contract verification
	expected = `{"root":"13558168455220559042747853958949063046226645447188878859760119761585093422436","siblings":["11620130507635441932056895853942898236773847390796721536119314875877874016518","5158240518874928563648144881543092238925265313977134167935552944620041388700"],"oldKey":"0","oldValue":"0","isOld0":false,"key":"2","value":"22","fnc":0}` //nolint:lll
	assert.Equal(t, expected, string(jCvp))
}
