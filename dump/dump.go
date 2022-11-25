package dump

import (
	"bytes"
	"context"
	"errors"

	"github.com/iden3/go-merkletree-sql/v3"
)

// DumpLeafs returns all the Leafs that exist under the given Root. If no Root
// is given (nil), it uses the current Root of the MerkleTree.
func DumpLeafs(ctx context.Context, rootKey *merkletree.Hash, mt *merkletree.MerkleTree) ([]byte, error) {
	var buf bytes.Buffer
	err := mt.Walk(ctx, rootKey, func(n *merkletree.Node) {
		if n.Type == merkletree.NodeTypeLeaf {
			buf.Grow(len(n.Entry[0]) + len(n.Entry[1]))
			buf.Write(n.Entry[0][:])
			buf.Write(n.Entry[1][:])
		}
	})
	return buf.Bytes(), err
}

// ImportDumpedLeafs parses and adds to the MerkleTree the dumped list of leafs
// from the DumpLeafs function.
func ImportDumpedLeafs(ctx context.Context, b []byte, mt *merkletree.MerkleTree) error {
	hashLn := len(merkletree.Hash{})
	nodeLn := hashLn * 2
	if len(b)%nodeLn != 0 {
		return errors.New("invalid input length")
	}
	for i := 0; i < len(b); i += nodeLn {
		var k, v merkletree.Hash
		copy(k[:], b[i:i+hashLn])
		copy(v[:], b[i+hashLn:i+(hashLn*2)])

		_, err := mt.Add(ctx, k.BigInt(), v.BigInt())
		if err != nil {
			return err
		}
	}
	return nil
}
