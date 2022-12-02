package merkletree

import (
	"fmt"
	"math/big"
)

// NodeType defines the type of node in the MT.
type NodeType byte

const (
	// NodeTypeMiddle indicates the type of middle Node that has children.
	NodeTypeMiddle NodeType = 0
	// NodeTypeLeaf indicates the type of leaf Node that contains a key &
	// value.
	NodeTypeLeaf NodeType = 1
	// NodeTypeEmpty indicates the type of empty Node.
	// Virtual node that is not stored in the database.
	// Also, this node haven't representation on tree.
	NodeTypeEmpty NodeType = 2
)

// Node is the struct that represents a node in the MT. The node should not be
// modified after creation because the cached key won't be updated.
type Node struct {
	// Type is the type of node in the tree.
	Type NodeType
	// ChildL is the left child of a middle node.
	ChildL *Hash
	// ChildR is the right child of a middle node.
	ChildR *Hash
	// Entry is the data stored in a leaf node.
	Entry [2]*Hash
	// key is a cache used to avoid recalculating key
	key *Hash
}

// NewNodeLeaf creates a new leaf node.
func NewNodeLeaf(k, v *Hash) *Node {
	return &Node{Type: NodeTypeLeaf, Entry: [2]*Hash{k, v}}
}

// NewNodeMiddle creates a new middle node.
func NewNodeMiddle(childL *Hash, childR *Hash) *Node {
	return &Node{Type: NodeTypeMiddle, ChildL: childL, ChildR: childR}
}

// NewNodeEmpty creates a new empty node.
func NewNodeEmpty() *Node {
	return &Node{Type: NodeTypeEmpty}
}

// NewNodeFromBytes creates a new node by parsing the input []byte.
func NewNodeFromBytes(b []byte) (*Node, error) {
	if len(b) < 1 {
		return nil, ErrNodeBytesBadSize
	}
	n := Node{Type: NodeType(b[0])}
	b = b[1:]
	switch n.Type {
	case NodeTypeMiddle:
		if len(b) != 2*ElemBytesLen {
			return nil, ErrNodeBytesBadSize
		}
		n.ChildL, n.ChildR = &Hash{}, &Hash{}
		copy(n.ChildL[:], b[:ElemBytesLen])
		copy(n.ChildR[:], b[ElemBytesLen:ElemBytesLen*2])
	case NodeTypeLeaf:
		if len(b) != 2*ElemBytesLen {
			return nil, ErrNodeBytesBadSize
		}
		n.Entry = [2]*Hash{{}, {}}
		copy(n.Entry[0][:], b[0:32])
		copy(n.Entry[1][:], b[32:64])
	case NodeTypeEmpty:
		break
	default:
		return nil, ErrInvalidNodeFound
	}
	return &n, nil
}

// LeafKey computes the key of a leaf node given the hIndex and hValue of the
// entry of the leaf.
func LeafKey(k, v *Hash) (*Hash, error) {
	return HashElemsKey(big.NewInt(1), k.BigInt(), v.BigInt())
}

// Key computes the key of the node by hashing the content in a specific way
// for each type of node.  This key is used as the hash of the merkle tree for
// each node.
func (n *Node) Key() (*Hash, error) {
	if n.key == nil { // Cache the key to avoid repeated hash computations.
		// NOTE: We are not using the type to calculate the hash!
		switch n.Type {
		case NodeTypeMiddle: // H(ChildL || ChildR)
			var err error
			n.key, err = HashElems(n.ChildL.BigInt(), n.ChildR.BigInt())
			if err != nil {
				return nil, err
			}
		case NodeTypeLeaf:
			var err error
			n.key, err = LeafKey(n.Entry[0], n.Entry[1])
			if err != nil {
				return nil, err
			}
		case NodeTypeEmpty: // Zero
			n.key = &HashZero
		default:
			n.key = &HashZero
		}
	}
	return n.key, nil
}

// Value returns the value of the node.  This is the content that is stored in
// the backend database.
func (n *Node) Value() []byte {
	switch n.Type {
	case NodeTypeMiddle: // {Type || ChildL || ChildR}
		return append([]byte{byte(n.Type)}, append(n.ChildL[:], n.ChildR[:]...)...)
	case NodeTypeLeaf: // {Type || Data...}
		return append([]byte{byte(n.Type)}, append(n.Entry[0][:], n.Entry[1][:]...)...)
	case NodeTypeEmpty: // {}
		return []byte{}
	default:
		return []byte{}
	}
}

// String outputs a string representation of a node (different for each type).
func (n *Node) String() string {
	switch n.Type {
	case NodeTypeMiddle: // {Type || ChildL || ChildR}
		return fmt.Sprintf("Middle L:%s R:%s", n.ChildL, n.ChildR)
	case NodeTypeLeaf: // {Type || Data...}
		return fmt.Sprintf("Leaf I:%v D:%v", n.Entry[0], n.Entry[1])
	case NodeTypeEmpty: // {}
		return "Empty"
	default:
		return "Invalid Node"
	}
}
