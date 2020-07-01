package merkletree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/db"
	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
)

const (
	// proofFlagsLen is the byte length of the flags in the proof header (first 32
	// bytes).
	proofFlagsLen = 2
	// ElemBytesLen is the length of the Hash byte array
	ElemBytesLen = 32
)

var (
	// ErrNodeKeyAlreadyExists is used when a node key already exists.
	ErrNodeKeyAlreadyExists = errors.New("node already exists")
	// ErrEntryIndexNotFound is used when no entry is found for an index.
	ErrEntryIndexNotFound = errors.New("node index not found in the DB")
	// ErrNodeDataBadSize is used when the data of a node has an incorrect
	// size and can't be parsed.
	ErrNodeDataBadSize = errors.New("node data has incorrect size in the DB")
	// ErrReachedMaxLevel is used when a traversal of the MT reaches the
	// maximum level.
	ErrReachedMaxLevel = errors.New("reached maximum level of the merkle tree")
	// ErrInvalidNodeFound is used when an invalid node is found and can't
	// be parsed.
	ErrInvalidNodeFound = errors.New("found an invalid node in the DB")
	// ErrInvalidProofBytes is used when a serialized proof is invalid.
	ErrInvalidProofBytes = errors.New("the serialized proof is invalid")
	// ErrInvalidDBValue is used when a value in the key value DB is
	// invalid (for example, it doen't contain a byte header and a []byte
	// body of at least len=1.
	ErrInvalidDBValue = errors.New("the value in the DB is invalid")
	// ErrEntryIndexAlreadyExists is used when the entry index already
	// exists in the tree.
	ErrEntryIndexAlreadyExists = errors.New("the entry index already exists in the tree")
	// ErrNotWritable is used when the MerkleTree is not writable and a write function is called
	ErrNotWritable = errors.New("Merkle Tree not writable")
	rootNodeValue  = []byte("currentroot")
	// HashZero is used at Empty nodes
	HashZero = Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

// Hash is the generic type stored in the MerkleTree
type Hash [32]byte

func (h Hash) String() string {
	return new(big.Int).SetBytes(h[:]).String()
}
func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// BigInt returns the *big.Int representation of the *Hash
func (h *Hash) BigInt() *big.Int {
	return new(big.Int).SetBytes(common.SwapEndianness(h[:]))
}

// NewHashFromBigInt returns a *Hash representation of the given *big.Int
func NewHashFromBigInt(b *big.Int) *Hash {
	r := &Hash{}
	copy(r[:], common.SwapEndianness(b.Bytes()))
	return r
}

// MerkleTree is the struct with the main elements of the MerkleTree
type MerkleTree struct {
	sync.RWMutex
	db        db.Storage
	rootKey   *Hash
	writable  bool
	maxLevels int
}

// NewMerkleTree loads a new Merkletree. If in the sotrage already exists one will open that one, if not, will create a new one.
func NewMerkleTree(storage db.Storage, maxLevels int) (*MerkleTree, error) {
	mt := MerkleTree{db: storage, maxLevels: maxLevels, writable: true}

	v, err := mt.db.Get(rootNodeValue)
	if err != nil {
		tx, err := mt.db.NewTx()
		if err != nil {
			return nil, err
		}
		mt.rootKey = &HashZero
		tx.Put(rootNodeValue, mt.rootKey[:])
		err = tx.Commit()
		if err != nil {
			return nil, err
		}
		return &mt, nil
	}
	mt.rootKey = &Hash{}
	copy(mt.rootKey[:], v)
	return &mt, nil
}

// Root returns the MerkleRoot
func (mt *MerkleTree) Root() *Hash {
	return mt.rootKey
}

// Add adds a Key & Value into the MerkleTree. Where the `k` determines the path from the Root to the Leaf.
func (mt *MerkleTree) Add(k, v *big.Int) error {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return ErrNotWritable
	}

	// verfy that the ElemBytes are valid and fit inside the Finite Field.
	if !cryptoUtils.CheckBigIntInField(k) {
		return errors.New("Key not inside the Finite Field")
	}
	if !cryptoUtils.CheckBigIntInField(v) {
		return errors.New("Value not inside the Finite Field")
	}

	tx, err := mt.db.NewTx()
	if err != nil {
		return err
	}
	mt.Lock()
	defer mt.Unlock()

	kHash := NewHashFromBigInt(k)
	vHash := NewHashFromBigInt(v)
	newNodeLeaf := NewNodeLeaf(kHash, vHash)
	path := getPath(mt.maxLevels, kHash[:])

	newRootKey, err := mt.addLeaf(tx, newNodeLeaf, mt.rootKey, 0, path)
	if err != nil {
		return err
	}
	mt.rootKey = newRootKey
	mt.dbInsert(tx, rootNodeValue, DBEntryTypeRoot, mt.rootKey[:])

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// pushLeaf recursively pushes an existing oldLeaf down until its path diverges
// from newLeaf, at which point both leafs are stored, all while updating the
// path.
func (mt *MerkleTree) pushLeaf(tx db.Tx, newLeaf *Node, oldLeaf *Node,
	lvl int, pathNewLeaf []bool, pathOldLeaf []bool) (*Hash, error) {
	if lvl > mt.maxLevels-2 {
		return nil, ErrReachedMaxLevel
	}
	var newNodeMiddle *Node
	if pathNewLeaf[lvl] == pathOldLeaf[lvl] { // We need to go deeper!
		nextKey, err := mt.pushLeaf(tx, newLeaf, oldLeaf, lvl+1, pathNewLeaf, pathOldLeaf)
		if err != nil {
			return nil, err
		}
		if pathNewLeaf[lvl] {
			newNodeMiddle = NewNodeMiddle(&HashZero, nextKey) // go right
		} else {
			newNodeMiddle = NewNodeMiddle(nextKey, &HashZero) // go left
		}
		return mt.addNode(tx, newNodeMiddle)
	} else {
		oldLeafKey, err := oldLeaf.Key()
		if err != nil {
			return nil, err
		}
		newLeafKey, err := newLeaf.Key()
		if err != nil {
			return nil, err
		}

		if pathNewLeaf[lvl] {
			newNodeMiddle = NewNodeMiddle(oldLeafKey, newLeafKey)
		} else {
			newNodeMiddle = NewNodeMiddle(newLeafKey, oldLeafKey)
		}
		// We can add newLeaf now.  We don't need to add oldLeaf because it's already in the tree.
		_, err = mt.addNode(tx, newLeaf)
		if err != nil {
			return nil, err
		}
		return mt.addNode(tx, newNodeMiddle)
	}
}

// addLeaf recursively adds a newLeaf in the MT while updating the path.
func (mt *MerkleTree) addLeaf(tx db.Tx, newLeaf *Node, key *Hash,
	lvl int, path []bool) (*Hash, error) {
	var err error
	var nextKey *Hash
	if lvl > mt.maxLevels-1 {
		return nil, ErrReachedMaxLevel
	}
	n, err := mt.GetNode(key)
	if err != nil {
		return nil, err
	}
	switch n.Type {
	case NodeTypeEmpty:
		// We can add newLeaf now
		return mt.addNode(tx, newLeaf)
	case NodeTypeLeaf:
		nKey := n.Entry[0]
		// Check if leaf node found contains the leaf node we are trying to add
		newLeafKey := newLeaf.Entry[0]
		if bytes.Equal(nKey[:], newLeafKey[:]) {
			return nil, ErrEntryIndexAlreadyExists
		}
		pathOldLeaf := getPath(mt.maxLevels, nKey[:])
		// We need to push newLeaf down until its path diverges from n's path
		return mt.pushLeaf(tx, newLeaf, n, lvl, path, pathOldLeaf)
	case NodeTypeMiddle:
		// We need to go deeper, continue traversing the tree, left or right depending on path
		var newNodeMiddle *Node
		if path[lvl] {
			nextKey, err = mt.addLeaf(tx, newLeaf, n.ChildR, lvl+1, path) // go right
			newNodeMiddle = NewNodeMiddle(n.ChildL, nextKey)
		} else {
			nextKey, err = mt.addLeaf(tx, newLeaf, n.ChildL, lvl+1, path) // go left
			newNodeMiddle = NewNodeMiddle(nextKey, n.ChildR)
		}
		if err != nil {
			return nil, err
		}
		// Update the node to reflect the modified child
		return mt.addNode(tx, newNodeMiddle)
	default:
		return nil, ErrInvalidNodeFound
	}
}

// addNode adds a node into the MT.  Empty nodes are not stored in the tree;
// they are all the same and assumed to always exist.
func (mt *MerkleTree) addNode(tx db.Tx, n *Node) (*Hash, error) {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return nil, ErrNotWritable
	}
	if n.Type == NodeTypeEmpty {
		return n.Key()
	}
	k, err := n.Key()
	if err != nil {
		return nil, err
	}
	v := n.Value()
	// Check that the node key doesn't already exist
	if _, err := tx.Get(k[:]); err == nil {
		return nil, ErrNodeKeyAlreadyExists
	}
	tx.Put(k[:], v)
	return k, nil
}

// dbGet is a helper function to get the node of a key from the internal
// storage.
func (mt *MerkleTree) dbGet(k []byte) (NodeType, []byte, error) {
	if bytes.Equal(k, HashZero[:]) {
		return 0, nil, nil
	}

	value, err := mt.db.Get(k)
	if err != nil {
		return 0, nil, err
	}

	if len(value) < 2 {
		return 0, nil, ErrInvalidDBValue
	}
	nodeType := value[0]
	nodeBytes := value[1:]

	return NodeType(nodeType), nodeBytes, nil
}

// dbInsert is a helper function to insert a node into a key in an open db
// transaction.
func (mt *MerkleTree) dbInsert(tx db.Tx, k []byte, t NodeType, data []byte) {
	v := append([]byte{byte(t)}, data...)
	tx.Put(k, v)
}

// GetNode gets a node by key from the MT.  Empty nodes are not stored in the
// tree; they are all the same and assumed to always exist.
func (mt *MerkleTree) GetNode(key *Hash) (*Node, error) {
	if bytes.Equal(key[:], HashZero[:]) {
		return NewNodeEmpty(), nil
	}
	nBytes, err := mt.db.Get(key[:])
	if err != nil {
		return nil, err
	}
	return NewNodeFromBytes(nBytes)
}

// getPath returns the binary path, from the root to the leaf.
func getPath(numLevels int, k []byte) []bool {
	path := make([]bool, numLevels)
	for n := 0; n < numLevels; n++ {
		path[n] = common.TestBit(k[:], uint(n))
	}
	return path
}

// NodeAux contains the auxiliary node used in a non-existence proof.
type NodeAux struct {
	Key   *Hash
	Value *Hash
}

// Proof defines the required elements for a MT proof of existence or non-existence.
type Proof struct {
	// existence indicates wether this is a proof of existence or non-existence.
	Existence bool
	// depth indicates how deep in the tree the proof goes.
	depth uint
	// notempties is a bitmap of non-empty Siblings found in Siblings.
	notempties [ElemBytesLen - proofFlagsLen]byte
	// Siblings is a list of non-empty sibling keys.
	Siblings []*Hash
	NodeAux  *NodeAux
}

// NewProofFromBytes parses a byte array into a Proof.
func NewProofFromBytes(bs []byte) (*Proof, error) {
	if len(bs) < ElemBytesLen {
		return nil, ErrInvalidProofBytes
	}
	p := &Proof{}
	if (bs[0] & 0x01) == 0 {
		p.Existence = true
	}
	p.depth = uint(bs[1])
	copy(p.notempties[:], bs[proofFlagsLen:ElemBytesLen])
	siblingBytes := bs[ElemBytesLen:]
	sibIdx := 0
	for i := uint(0); i < p.depth; i++ {
		if common.TestBitBigEndian(p.notempties[:], i) {
			if len(siblingBytes) < (sibIdx+1)*ElemBytesLen {
				return nil, ErrInvalidProofBytes
			}
			var sib Hash
			copy(sib[:], siblingBytes[sibIdx*ElemBytesLen:(sibIdx+1)*ElemBytesLen])
			p.Siblings = append(p.Siblings, &sib)
			sibIdx++
		}
	}

	if !p.Existence && ((bs[0] & 0x02) != 0) {
		p.NodeAux = &NodeAux{Key: &Hash{}, Value: &Hash{}}
		nodeAuxBytes := siblingBytes[len(p.Siblings)*ElemBytesLen:]
		if len(nodeAuxBytes) != 2*ElemBytesLen {
			return nil, ErrInvalidProofBytes
		}
		copy(p.NodeAux.Key[:], nodeAuxBytes[:ElemBytesLen])
		copy(p.NodeAux.Value[:], nodeAuxBytes[ElemBytesLen:2*ElemBytesLen])
	}
	return p, nil
}

// Bytes serializes a Proof into a byte array.
func (p *Proof) Bytes() []byte {
	bsLen := proofFlagsLen + len(p.notempties) + ElemBytesLen*len(p.Siblings)
	if p.NodeAux != nil {
		bsLen += 2 * ElemBytesLen
	}
	bs := make([]byte, bsLen)

	if !p.Existence {
		bs[0] |= 0x01
	}
	bs[1] = byte(p.depth)
	copy(bs[proofFlagsLen:len(p.notempties)+proofFlagsLen], p.notempties[:])
	siblingsBytes := bs[len(p.notempties)+proofFlagsLen:]
	for i, k := range p.Siblings {
		copy(siblingsBytes[i*ElemBytesLen:(i+1)*ElemBytesLen], k[:])
	}
	if p.NodeAux != nil {
		bs[0] |= 0x02
		copy(bs[len(bs)-2*ElemBytesLen:], p.NodeAux.Key[:])
		copy(bs[len(bs)-1*ElemBytesLen:], p.NodeAux.Value[:])
	}
	return bs
}

// SiblingsFromProof returns all the siblings of the proof. This function is used to generate the siblings input for the circom circuits.
func SiblingsFromProof(proof *Proof) []*Hash {
	sibIdx := 0
	var siblings []*Hash
	for lvl := 0; lvl < int(proof.depth); lvl++ {
		if common.TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblings = append(siblings, proof.Siblings[sibIdx])
			sibIdx++
		} else {
			siblings = append(siblings, &HashZero)
		}
	}
	return siblings
}

func (p *Proof) AllSiblings() []*Hash {
	return SiblingsFromProof(p)
}

func (p *Proof) AllSiblingsCircom(levels int) []*big.Int {
	siblings := p.AllSiblings()
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels; i++ {
		siblings = append(siblings, &HashZero)
	}
	siblings = append(siblings, &HashZero) // add extra level for circom compatibility
	siblingsBigInt := make([]*big.Int, len(siblings))
	for i, sibling := range siblings {
		siblingsBigInt[i] = sibling.BigInt()
	}
	return siblingsBigInt
}

// GenerateProof generates the proof of existence (or non-existence) of an
// Entry's hash Index for a Merkle Tree given the root.
// If the rootKey is nil, the current merkletree root is used
func (mt *MerkleTree) GenerateProof(k *big.Int, rootKey *Hash) (*Proof, error) {
	p := &Proof{}
	var siblingKey *Hash

	kHash := NewHashFromBigInt(k)
	path := getPath(mt.maxLevels, kHash[:])
	if rootKey == nil {
		rootKey = mt.Root()
	}
	nextKey := rootKey
	for p.depth = 0; p.depth < uint(mt.maxLevels); p.depth++ {
		n, err := mt.GetNode(nextKey)
		if err != nil {
			return nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return p, nil
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.Entry[0][:]) {
				p.Existence = true
				return p, nil
			} else {
				// We found a leaf whose entry didn't match hIndex
				p.NodeAux = &NodeAux{Key: n.Entry[0], Value: n.Entry[1]}
				return p, nil
			}
		case NodeTypeMiddle:
			if path[p.depth] {
				nextKey = n.ChildR
				siblingKey = n.ChildL
			} else {
				nextKey = n.ChildL
				siblingKey = n.ChildR
			}
		default:
			return nil, ErrInvalidNodeFound
		}
		if !bytes.Equal(siblingKey[:], HashZero[:]) {
			common.SetBitBigEndian(p.notempties[:], uint(p.depth))
			p.Siblings = append(p.Siblings, siblingKey)
		}
	}
	return nil, ErrEntryIndexNotFound
}

// VerifyProof verifies the Merkle Proof for the entry and root.
func VerifyProof(rootKey *Hash, proof *Proof, k, v *big.Int) bool {
	rootFromProof, err := RootFromProof(proof, k, v)
	if err != nil {
		return false
	}
	return bytes.Equal(rootKey[:], rootFromProof[:])
}

// RootFromProof calculates the root that would correspond to a tree whose
// siblings are the ones in the proof with the claim hashing to hIndex and
// hValue.
func RootFromProof(proof *Proof, k, v *big.Int) (*Hash, error) {
	kHash := NewHashFromBigInt(k)
	vHash := NewHashFromBigInt(v)
	sibIdx := len(proof.Siblings) - 1
	var err error
	var midKey *Hash
	if proof.Existence {
		midKey, err = LeafKey(kHash, vHash)
		if err != nil {
			return nil, err
		}
	} else {
		if proof.NodeAux == nil {
			midKey = &HashZero
		} else {
			if bytes.Equal(kHash[:], proof.NodeAux.Key[:]) {
				return nil, fmt.Errorf("Non-existence proof being checked against hIndex equal to nodeAux")
			}
			midKey, err = LeafKey(proof.NodeAux.Key, proof.NodeAux.Value)
			if err != nil {
				return nil, err
			}
		}
	}
	path := getPath(int(proof.depth), kHash[:])
	var siblingKey *Hash
	for lvl := int(proof.depth) - 1; lvl >= 0; lvl-- {
		if common.TestBitBigEndian(proof.notempties[:], uint(lvl)) {
			siblingKey = proof.Siblings[sibIdx]
			sibIdx--
		} else {
			siblingKey = &HashZero
		}
		if path[lvl] {
			midKey, err = NewNodeMiddle(siblingKey, midKey).Key()
			if err != nil {
				return nil, err
			}
		} else {
			midKey, err = NewNodeMiddle(midKey, siblingKey).Key()
			if err != nil {
				return nil, err
			}
		}
	}
	return midKey, nil
}

// walk is a helper recursive function to iterate over all tree branches
func (mt *MerkleTree) walk(key *Hash, f func(*Node)) error {
	n, err := mt.GetNode(key)
	if err != nil {
		return err
	}
	switch n.Type {
	case NodeTypeEmpty:
		f(n)
	case NodeTypeLeaf:
		f(n)
	case NodeTypeMiddle:
		f(n)
		if err := mt.walk(n.ChildL, f); err != nil {
			return err
		}
		if err := mt.walk(n.ChildR, f); err != nil {
			return err
		}
	default:
		return ErrInvalidNodeFound
	}
	return nil
}

// Walk iterates over all the branches of a MerkleTree with the given rootKey
// if rootKey is nil, it will get the current RootKey of the current state of the MerkleTree.
// For each node, it calls the f function given in the parameters.
// See some examples of the Walk function usage in the merkletree_test.go
// test functions: TestMTWalk, TestMTWalkGraphViz, TestMTWalkDumpClaims
func (mt *MerkleTree) Walk(rootKey *Hash, f func(*Node)) error {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	err := mt.walk(rootKey, f)
	return err
}

// GraphViz uses Walk function to generate a string GraphViz representation of the
// tree and writes it to w
func (mt *MerkleTree) GraphViz(w io.Writer, rootKey *Hash) error {
	fmt.Fprintf(w, `digraph hierarchy {
node [fontname=Monospace,fontsize=10,shape=box]
`)
	cnt := 0
	var errIn error
	err := mt.Walk(rootKey, func(n *Node) {
		k, err := n.Key()
		if err != nil {
			errIn = err
		}
		switch n.Type {
		case NodeTypeEmpty:
		case NodeTypeLeaf:
			fmt.Fprintf(w, "\"%v\" [style=filled];\n", k.BigInt().String())
		case NodeTypeMiddle:
			lr := [2]string{n.ChildL.BigInt().String(), n.ChildR.BigInt().String()}
			for i := range lr {
				if lr[i] == "0" {
					lr[i] = fmt.Sprintf("empty%v", cnt)
					fmt.Fprintf(w, "\"%v\" [style=dashed,label=0];\n", lr[i])
					cnt++
				}
			}
			fmt.Fprintf(w, "\"%v\" -> {\"%v\" \"%v\"}\n", k.BigInt().String(), lr[0], lr[1])
		default:
		}
	})
	fmt.Fprintf(w, "}\n")
	if errIn != nil {
		return errIn
	}
	return err
}

// PrintGraphViz prints directly the GraphViz() output
func (mt *MerkleTree) PrintGraphViz(rootKey *Hash) error {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	w := bytes.NewBufferString("")
	fmt.Fprintf(w, "--------\nGraphViz of the MerkleTree with RootKey "+rootKey.BigInt().String()+"\n")
	err := mt.GraphViz(w, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "End of GraphViz of the MerkleTree with RootKey "+rootKey.BigInt().String()+"\n--------\n")

	fmt.Println(w)
	return nil
}
