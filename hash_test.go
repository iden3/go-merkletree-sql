package merkletree

import (
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/constants"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashParsers(t *testing.T) {
	h0 := NewHashFromBigInt(big.NewInt(0))
	assert.Equal(t, "0", h0.String())
	h1 := NewHashFromBigInt(big.NewInt(1))
	assert.Equal(t, "1", h1.String())
	h10 := NewHashFromBigInt(big.NewInt(10))
	assert.Equal(t, "10", h10.String())

	h7l := NewHashFromBigInt(big.NewInt(1234567))
	assert.Equal(t, "1234567", h7l.String())
	h8l := NewHashFromBigInt(big.NewInt(12345678))
	assert.Equal(t, "12345678...", h8l.String())

	b, ok := new(big.Int).SetString("4932297968297298434239270129193057052722409868268166443802652458940273154854", 10) //nolint:lll
	assert.True(t, ok)
	h := NewHashFromBigInt(b)
	assert.Equal(t, "4932297968297298434239270129193057052722409868268166443802652458940273154854", h.BigInt().String()) //nolint:lll
	assert.Equal(t, "49322979...", h.String())
	assert.Equal(t, "265baaf161e875c372d08e50f52abddc01d32efc93e90290bb8b3d9ceb94e70a", h.Hex())

	b1, err := NewBigIntFromHashBytes(b.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, new(big.Int).SetBytes(b.Bytes()).String(), b1.String())

	b2, err := NewHashFromBytes(b.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, b.String(), b2.BigInt().String())

	h2, err := NewHashFromHex(h.Hex())
	assert.Nil(t, err)
	assert.Equal(t, h, h2)
	_, err = NewHashFromHex("0x12")
	assert.NotNil(t, err)

	// check limits
	a := new(big.Int).Sub(constants.Q, big.NewInt(1))
	testHashParsers(t, a)
	a = big.NewInt(int64(1))
	testHashParsers(t, a)
}

func testHashParsers(t *testing.T, a *big.Int) {
	require.True(t, cryptoUtils.CheckBigIntInField(a))
	h := NewHashFromBigInt(a)
	assert.Equal(t, a, h.BigInt())
	hFromBytes, err := NewHashFromBytes(h.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, h, hFromBytes)
	assert.Equal(t, a, hFromBytes.BigInt())
	assert.Equal(t, a.String(), hFromBytes.BigInt().String())
	hFromHex, err := NewHashFromHex(h.Hex())
	assert.Nil(t, err)
	assert.Equal(t, h, hFromHex)

	aBIFromHBytes, err := NewBigIntFromHashBytes(h.Bytes())
	assert.Nil(t, err)
	assert.Equal(t, a, aBIFromHBytes)
	assert.Equal(t, new(big.Int).SetBytes(a.Bytes()).String(), aBIFromHBytes.String())
}
