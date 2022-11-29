package merkletree

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// NOTICE: go-merkletree-sql uses BigEndian for bits representation!
func TestGetPath(t *testing.T) {
	tests := []struct {
		name      string
		toConvert *big.Int
		maxLevel  int
		expected  []bool
	}{
		{
			name:      "7 to 111",
			toConvert: big.NewInt(7),
			maxLevel:  3,
			expected:  []bool{true, true, true},
		},
		{
			name:      "7 to 1110",
			toConvert: big.NewInt(7),
			maxLevel:  4,
			expected:  []bool{true, true, true, false},
		},
		{
			name:      "15 to 1111",
			toConvert: big.NewInt(15),
			maxLevel:  4,
			expected:  []bool{true, true, true, true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := getPath(tt.maxLevel, SwapEndianness(tt.toConvert.Bytes()))
			require.Equal(t, tt.expected, actual)
		})
	}
}
