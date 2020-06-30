package merkletree

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-core/db"
	"github.com/stretchr/testify/assert"
)

func TestNewTree(t *testing.T) {
	mt, err := NewMerkleTree(db.NewMemoryStorage(), 10)
	assert.Nil(t, err)
	assert.Equal(t, "0", mt.Root().String())

	// test vectors generated using https://github.com/iden3/circomlib smt.js
	err = mt.Add(big.NewInt(1), big.NewInt(2))
	assert.Nil(t, err)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154854", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(33), big.NewInt(44))
	assert.Nil(t, err)
	assert.Equal(t, "13563340744765267202993741297198970774200042973817962221376874695587906013050", mt.Root().BigInt().String())

	err = mt.Add(big.NewInt(1234), big.NewInt(9876))
	assert.Nil(t, err)
	assert.Equal(t, "16970503620176669663662021947486532860010370357132361783766545149750777353066", mt.Root().BigInt().String())
}
