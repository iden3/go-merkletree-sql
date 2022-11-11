package graph

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/iden3/go-merkletree-sql/v2"
)

const numCharPrint = 8

// PrintGraphViz prints directly the GraphViz() output
func PrintGraphViz(ctx context.Context, withRootKey *merkletree.Hash, mt *merkletree.MerkleTree) error {
	if withRootKey == nil {
		withRootKey = mt.Root()
	}
	w := bytes.NewBufferString("")
	fmt.Fprintf(w,
		"--------\nGraphViz of the MerkleTree with RootKey "+withRootKey.BigInt().String()+"\n")
	err := mt.GraphViz(ctx, w, withRootKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(w,
		"End of GraphViz of the MerkleTree with RootKey "+withRootKey.BigInt().String()+"\n--------\n")

	fmt.Println(w)
	return nil
}

// GraphViz uses Walk function to generate a string GraphViz representation of
// the tree and writes it to w
func GraphViz(ctx context.Context, w io.Writer, withRootKey *merkletree.Hash, mt *merkletree.MerkleTree) error {
	fmt.Fprintf(w, `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
`)
	cnt := 0
	var errIn error
	err := mt.Walk(ctx, withRootKey, func(n *merkletree.Node) {
		k, err := n.Key()
		if err != nil {
			errIn = err
		}
		switch n.Type {
		case merkletree.NodeTypeEmpty:
		case merkletree.NodeTypeLeaf:
			fmt.Fprintf(w, "\"%v\" [style=filled];\n", k.String())
		case merkletree.NodeTypeMiddle:
			lr := [2]string{n.ChildL.String(), n.ChildR.String()}
			emptyNodes := ""
			for i := range lr {
				if lr[i] == "0" {
					lr[i] = fmt.Sprintf("empty%v", cnt)
					emptyNodes += fmt.Sprintf("\"%v\" [style=dashed,label=0];\n",
						lr[i])
					cnt++
				}
			}
			fmt.Fprintf(w, "\"%v\" -> {\"%v\" \"%v\"}\n", k.String(), lr[0],
				lr[1])
			fmt.Fprint(w, emptyNodes)
		default:
		}
	})
	fmt.Fprintf(w, "}\n")
	if errIn != nil {
		return errIn
	}
	return err
}

// HashShortString returns decimal representation in string format of the Hash
func HashShortString(hash *merkletree.Hash) string {
	s := hash.BigInt().String()
	if len(s) < numCharPrint {
		return s
	}
	return s[0:numCharPrint] + "..."
}
