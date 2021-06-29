package merkletree

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	cryptoUtils "github.com/iden3/go-iden3-crypto/utils"
)

const (
	// proofFlagsLen is the byte length of the flags in the proof header
	// (first 32 bytes).
	proofFlagsLen = 2

	numCharPrint = 8

	// IndexLen indicates how many elements are used for the index.
	IndexLen = 4
	// DataLen indicates how many elements are used for the data.
	DataLen = 8
)

var (
	// ErrNodeKeyAlreadyExists is used when a node key already exists.
	ErrNodeKeyAlreadyExists = errors.New("key already exists")
	// ErrKeyNotFound is used when a key is not found in the MerkleTree.
	ErrKeyNotFound = errors.New("Key not found in the MerkleTree")
	// ErrNodeBytesBadSize is used when the data of a node has an incorrect
	// size and can't be parsed.
	ErrNodeBytesBadSize = errors.New("node data has incorrect size in the DB")
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
	// ErrNotWritable is used when the MerkleTree is not writable and a
	// write function is called
	ErrNotWritable = errors.New("Merkle Tree not writable")

	dbKeyRootNode = []byte("currentroot")
)

// MerkleTree is the struct with the main elements of the MerkleTree
type MerkleTree struct {
	sync.RWMutex
	db        Storage
	rootKey   *Hash
	writable  bool
	maxLevels int
}

// NewMerkleTree loads a new MerkleTree. If in the storage already exists one
// will open that one, if not, will create a new one.
func NewMerkleTree(storage Storage, maxLevels int) (*MerkleTree, error) {
	mt := MerkleTree{db: storage, maxLevels: maxLevels, writable: true}

	root, err := mt.dbGetRoot()
	if err == ErrNotFound {
		tx, err := mt.db.NewTx()
		if err != nil {
			return nil, err
		}
		mt.rootKey = &HashZero
		err = tx.SetRoot(mt.rootKey)
		if err != nil {
			return nil, err
		}
		err = tx.Commit()
		if err != nil {
			return nil, err
		}
		return &mt, nil
	} else if err != nil {
		return nil, err
	}
	mt.rootKey = root
	return &mt, nil
}

func (mt *MerkleTree) dbGetRoot() (*Hash, error) {
	hash, err := mt.db.GetRoot()
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// DB returns the MerkleTree.DB()
func (mt *MerkleTree) DB() Storage {
	return mt.db
}

// Root returns the MerkleRoot
func (mt *MerkleTree) Root() *Hash {
	return mt.rootKey
}

// MaxLevels returns the MT maximum level
func (mt *MerkleTree) MaxLevels() int {
	return mt.maxLevels
}

// Snapshot returns a read-only copy of the MerkleTree
func (mt *MerkleTree) Snapshot(rootKey *Hash) (*MerkleTree, error) {
	mt.RLock()
	defer mt.RUnlock()
	_, err := mt.GetNode(rootKey)
	if err != nil {
		return nil, err
	}
	return &MerkleTree{db: mt.db, maxLevels: mt.maxLevels, rootKey: rootKey, writable: false}, nil
}

// Add adds a Key & Value into the MerkleTree. Where the `k` determines the
// path from the Root to the Leaf.
func (mt *MerkleTree) Add(k, v *big.Int) error {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return ErrNotWritable
	}

	// verify that k & v are valid and fit inside the Finite Field.
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
	err = mt.setCurrentRoot(tx, mt.rootKey)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// AddEntry adds the Entry to the MerkleTree
func (mt *MerkleTree) AddEntry(e *Entry) error {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return ErrNotWritable
	}
	// verify that the ElemBytes are valid and fit inside the mimc7 field.
	if !CheckEntryInField(*e) {
		return errors.New("Elements not inside the Finite Field over R")
	}
	tx, err := mt.db.NewTx()
	if err != nil {
		return err
	}
	mt.Lock()
	defer mt.Unlock()

	hIndex, err := e.HIndex()
	if err != nil {
		return err
	}
	hValue, err := e.HValue()
	if err != nil {
		return err
	}
	newNodeLeaf := NewNodeLeaf(hIndex, hValue)
	path := getPath(mt.maxLevels, hIndex[:])

	newRootKey, err := mt.addLeaf(tx, newNodeLeaf, mt.rootKey, 0, path)
	if err != nil {
		return err
	}
	mt.rootKey = newRootKey
	err = mt.setCurrentRoot(tx, mt.rootKey)
	if err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// AddAndGetCircomProof does an Add, and returns a CircomProcessorProof
func (mt *MerkleTree) AddAndGetCircomProof(k,
	v *big.Int) (*CircomProcessorProof, error) {
	var cp CircomProcessorProof
	cp.Fnc = 2
	cp.OldRoot = mt.rootKey
	gotK, gotV, _, err := mt.Get(k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	cp.OldKey = NewHashFromBigInt(gotK)
	cp.OldValue = NewHashFromBigInt(gotV)
	if bytes.Equal(cp.OldKey[:], HashZero[:]) {
		cp.IsOld0 = true
	}
	_, _, siblings, err := mt.Get(k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	cp.Siblings = CircomSiblingsFromSiblings(siblings, mt.maxLevels)

	err = mt.Add(k, v)
	if err != nil {
		return nil, err
	}

	cp.NewKey = NewHashFromBigInt(k)
	cp.NewValue = NewHashFromBigInt(v)
	cp.NewRoot = mt.rootKey

	return &cp, nil
}

// pushLeaf recursively pushes an existing oldLeaf down until its path diverges
// from newLeaf, at which point both leafs are stored, all while updating the
// path.
func (mt *MerkleTree) pushLeaf(tx Tx, newLeaf *Node, oldLeaf *Node, lvl int,
	pathNewLeaf []bool, pathOldLeaf []bool) (*Hash, error) {
	if lvl > mt.maxLevels-2 {
		return nil, ErrReachedMaxLevel
	}
	var newNodeMiddle *Node
	if pathNewLeaf[lvl] == pathOldLeaf[lvl] { // We need to go deeper!
		nextKey, err := mt.pushLeaf(tx, newLeaf, oldLeaf, lvl+1, pathNewLeaf, pathOldLeaf)
		if err != nil {
			return nil, err
		}
		if pathNewLeaf[lvl] { // go right
			newNodeMiddle = NewNodeMiddle(&HashZero, nextKey)
		} else { // go left
			newNodeMiddle = NewNodeMiddle(nextKey, &HashZero)
		}
		return mt.addNode(tx, newNodeMiddle)
	}
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
	// We can add newLeaf now.  We don't need to add oldLeaf because it's
	// already in the tree.
	_, err = mt.addNode(tx, newLeaf)
	if err != nil {
		return nil, err
	}
	return mt.addNode(tx, newNodeMiddle)
}

// addLeaf recursively adds a newLeaf in the MT while updating the path.
func (mt *MerkleTree) addLeaf(tx Tx, newLeaf *Node, key *Hash,
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
		// Check if leaf node found contains the leaf node we are
		// trying to add
		newLeafKey := newLeaf.Entry[0]
		if bytes.Equal(nKey[:], newLeafKey[:]) {
			return nil, ErrEntryIndexAlreadyExists
		}
		pathOldLeaf := getPath(mt.maxLevels, nKey[:])
		// We need to push newLeaf down until its path diverges from
		// n's path
		return mt.pushLeaf(tx, newLeaf, n, lvl, path, pathOldLeaf)
	case NodeTypeMiddle:
		// We need to go deeper, continue traversing the tree, left or
		// right depending on path
		var newNodeMiddle *Node
		if path[lvl] { // go right
			nextKey, err = mt.addLeaf(tx, newLeaf, n.ChildR, lvl+1, path)
			newNodeMiddle = NewNodeMiddle(n.ChildL, nextKey)
		} else { // go left
			nextKey, err = mt.addLeaf(tx, newLeaf, n.ChildL, lvl+1, path)
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
func (mt *MerkleTree) addNode(tx Tx, n *Node) (*Hash, error) {
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
	//v := n.Value()
	// Check that the node key doesn't already exist
	if _, err := tx.Get(k[:]); err == nil {
		return nil, ErrNodeKeyAlreadyExists
	}
	err = tx.Put(k[:], n)
	return k, err
}

// updateNode updates an existing node in the MT.  Empty nodes are not stored
// in the tree; they are all the same and assumed to always exist.
func (mt *MerkleTree) updateNode(tx Tx, n *Node) (*Hash, error) {
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
	//v := n.Value()
	err = tx.Put(k[:], n)
	return k, err
}

// Get returns the value of the leaf for the given key
func (mt *MerkleTree) Get(k *big.Int) (*big.Int, *big.Int, []*Hash, error) {
	// verify that k is valid and fits inside the Finite Field.
	if !cryptoUtils.CheckBigIntInField(k) {
		return nil, nil, nil, errors.New("Key not inside the Finite Field")
	}

	kHash := NewHashFromBigInt(k)
	path := getPath(mt.maxLevels, kHash[:])

	nextKey := mt.rootKey
	siblings := []*Hash{}
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(nextKey)
		if err != nil {
			return nil, nil, nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return big.NewInt(0), big.NewInt(0), siblings, ErrKeyNotFound
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.Entry[0][:]) {
				return n.Entry[0].BigInt(), n.Entry[1].BigInt(), siblings, nil
			}
			return n.Entry[0].BigInt(), n.Entry[1].BigInt(), siblings, ErrKeyNotFound
		case NodeTypeMiddle:
			if path[i] {
				nextKey = n.ChildR
				siblings = append(siblings, n.ChildL)
			} else {
				nextKey = n.ChildL
				siblings = append(siblings, n.ChildR)
			}
		default:
			return nil, nil, nil, ErrInvalidNodeFound
		}
	}

	return nil, nil, nil, ErrReachedMaxLevel
}

// Update updates the value of a specified key in the MerkleTree, and updates
// the path from the leaf to the Root with the new values. Returns the
// CircomProcessorProof.
func (mt *MerkleTree) Update(k, v *big.Int) (*CircomProcessorProof, error) {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return nil, ErrNotWritable
	}

	// verify that k & v are valid and fit inside the Finite Field.
	if !cryptoUtils.CheckBigIntInField(k) {
		return nil, errors.New("Key not inside the Finite Field")
	}
	if !cryptoUtils.CheckBigIntInField(v) {
		return nil, errors.New("Key not inside the Finite Field")
	}
	tx, err := mt.db.NewTx()
	if err != nil {
		return nil, err
	}
	mt.Lock()
	defer mt.Unlock()

	kHash := NewHashFromBigInt(k)
	vHash := NewHashFromBigInt(v)
	path := getPath(mt.maxLevels, kHash[:])

	var cp CircomProcessorProof
	cp.Fnc = 1
	cp.OldRoot = mt.rootKey
	cp.OldKey = kHash
	cp.NewKey = kHash
	cp.NewValue = vHash

	nextKey := mt.rootKey
	siblings := []*Hash{}
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(nextKey)
		if err != nil {
			return nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return nil, ErrKeyNotFound
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.Entry[0][:]) {
				cp.OldValue = n.Entry[1]
				cp.Siblings = CircomSiblingsFromSiblings(siblings, mt.maxLevels)
				// update leaf and upload to the root
				newNodeLeaf := NewNodeLeaf(kHash, vHash)
				_, err := mt.updateNode(tx, newNodeLeaf)
				if err != nil {
					return nil, err
				}
				newRootKey, err :=
					mt.recalculatePathUntilRoot(tx, path, newNodeLeaf, siblings)
				if err != nil {
					return nil, err
				}
				mt.rootKey = newRootKey
				err = mt.setCurrentRoot(tx, mt.rootKey)
				if err != nil {
					return nil, err
				}
				cp.NewRoot = newRootKey
				if err := tx.Commit(); err != nil {
					return nil, err
				}
				return &cp, nil
			}
			return nil, ErrKeyNotFound
		case NodeTypeMiddle:
			if path[i] {
				nextKey = n.ChildR
				siblings = append(siblings, n.ChildL)
			} else {
				nextKey = n.ChildL
				siblings = append(siblings, n.ChildR)
			}
		default:
			return nil, ErrInvalidNodeFound
		}
	}

	return nil, ErrKeyNotFound
}

// Delete removes the specified Key from the MerkleTree and updates the path
// from the deleted key to the Root with the new values.  This method removes
// the key from the MerkleTree, but does not remove the old nodes from the
// key-value database; this means that if the tree is accessed by an old Root
// where the key was not deleted yet, the key will still exist. If is desired
// to remove the key-values from the database that are not under the current
// Root, an option could be to dump all the leaves (using mt.DumpLeafs) and
// import them in a new MerkleTree in a new database (using
// mt.ImportDumpedLeafs), but this will loose all the Root history of the
// MerkleTree
func (mt *MerkleTree) Delete(k *big.Int) error {
	// verify that the MerkleTree is writable
	if !mt.writable {
		return ErrNotWritable
	}

	// verify that k is valid and fits inside the Finite Field.
	if !cryptoUtils.CheckBigIntInField(k) {
		return errors.New("Key not inside the Finite Field")
	}
	tx, err := mt.db.NewTx()
	if err != nil {
		return err
	}
	mt.Lock()
	defer mt.Unlock()

	kHash := NewHashFromBigInt(k)
	path := getPath(mt.maxLevels, kHash[:])

	nextKey := mt.rootKey
	siblings := []*Hash{}
	for i := 0; i < mt.maxLevels; i++ {
		n, err := mt.GetNode(nextKey)
		if err != nil {
			return err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return ErrKeyNotFound
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.Entry[0][:]) {
				// remove and go up with the sibling
				err = mt.rmAndUpload(tx, path, kHash, siblings)
				return err
			}
			return ErrKeyNotFound
		case NodeTypeMiddle:
			if path[i] {
				nextKey = n.ChildR
				siblings = append(siblings, n.ChildL)
			} else {
				nextKey = n.ChildL
				siblings = append(siblings, n.ChildR)
			}
		default:
			return ErrInvalidNodeFound
		}
	}

	return ErrKeyNotFound
}

// rmAndUpload removes the key, and goes up until the root updating all the
// nodes with the new values.
func (mt *MerkleTree) rmAndUpload(tx Tx, path []bool, kHash *Hash, siblings []*Hash) error {
	if len(siblings) == 0 {
		mt.rootKey = &HashZero
		err := mt.setCurrentRoot(tx, mt.rootKey)
		if err != nil {
			return err
		}
		return tx.Commit()
	}

	toUpload := siblings[len(siblings)-1]
	if len(siblings) < 2 { //nolint:gomnd
		mt.rootKey = siblings[0]
		err := mt.setCurrentRoot(tx, mt.rootKey)
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	for i := len(siblings) - 2; i >= 0; i-- { //nolint:gomnd
		if !bytes.Equal(siblings[i][:], HashZero[:]) {
			var newNode *Node
			if path[i] {
				newNode = NewNodeMiddle(siblings[i], toUpload)
			} else {
				newNode = NewNodeMiddle(toUpload, siblings[i])
			}
			_, err := mt.addNode(tx, newNode)
			if err != ErrNodeKeyAlreadyExists && err != nil {
				return err
			}
			// go up until the root
			newRootKey, err := mt.recalculatePathUntilRoot(tx, path, newNode,
				siblings[:i])
			if err != nil {
				return err
			}
			mt.rootKey = newRootKey
			err = mt.setCurrentRoot(tx, mt.rootKey)
			if err != nil {
				return err
			}
			break
		}
		// if i==0 (root position), stop and store the sibling of the
		// deleted leaf as root
		if i == 0 {
			mt.rootKey = toUpload
			err := mt.setCurrentRoot(tx, mt.rootKey)
			if err != nil {
				return err
			}
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// recalculatePathUntilRoot recalculates the nodes until the Root
func (mt *MerkleTree) recalculatePathUntilRoot(tx Tx, path []bool, node *Node,
	siblings []*Hash) (*Hash, error) {
	for i := len(siblings) - 1; i >= 0; i-- {
		nodeKey, err := node.Key()
		if err != nil {
			return nil, err
		}
		if path[i] {
			node = NewNodeMiddle(siblings[i], nodeKey)
		} else {
			node = NewNodeMiddle(nodeKey, siblings[i])
		}
		_, err = mt.addNode(tx, node)
		if err != ErrNodeKeyAlreadyExists && err != nil {
			return nil, err
		}
	}

	// return last node added, which is the root
	nodeKey, err := node.Key()
	return nodeKey, err
}

// setCurrentRoot is a helper function to update current root in an open db
// transaction.
func (mt *MerkleTree) setCurrentRoot(tx Tx, hash *Hash) error {
	return tx.SetRoot(hash)
}

// GetNode gets a node by key from the MT.  Empty nodes are not stored in the
// tree; they are all the same and assumed to always exist.
func (mt *MerkleTree) GetNode(key *Hash) (*Node, error) {
	if bytes.Equal(key[:], HashZero[:]) {
		return NewNodeEmpty(), nil
	}
	n, err := mt.db.Get(key[:])
	if err != nil {
		return nil, err
	}
	return n, nil
}

// getPath returns the binary path, from the root to the leaf.
func getPath(numLevels int, k []byte) []bool {
	path := make([]bool, numLevels)
	for n := 0; n < numLevels; n++ {
		path[n] = TestBit(k[:], uint(n))
	}
	return path
}

// NodeAux contains the auxiliary node used in a non-existence proof.
type NodeAux struct {
	Key   *Hash
	Value *Hash
}

// CircomSiblingsFromSiblings returns the full siblings compatible with circom
func CircomSiblingsFromSiblings(siblings []*Hash, levels int) []*Hash {
	// Add the rest of empty levels to the siblings
	for i := len(siblings); i < levels+1; i++ {
		siblings = append(siblings, &HashZero)
	}
	return siblings
}

// CircomProcessorProof defines the ProcessorProof compatible with circom. Is
// the data of the proof between the transition from one state to another.
type CircomProcessorProof struct {
	OldRoot  *Hash   `json:"oldRoot"`
	NewRoot  *Hash   `json:"newRoot"`
	Siblings []*Hash `json:"siblings"`
	OldKey   *Hash   `json:"oldKey"`
	OldValue *Hash   `json:"oldValue"`
	NewKey   *Hash   `json:"newKey"`
	NewValue *Hash   `json:"newValue"`
	IsOld0   bool    `json:"isOld0"`
	// 0: NOP, 1: Update, 2: Insert, 3: Delete
	Fnc int `json:"fnc"`
}

// String returns a human readable string representation of the
// CircomProcessorProof
func (p CircomProcessorProof) String() string {
	buf := bytes.NewBufferString("{")
	fmt.Fprintf(buf, "	OldRoot: %v,\n", p.OldRoot)
	fmt.Fprintf(buf, "	NewRoot: %v,\n", p.NewRoot)
	fmt.Fprintf(buf, "	Siblings: [\n		")
	for _, s := range p.Siblings {
		fmt.Fprintf(buf, "%v, ", s)
	}
	fmt.Fprintf(buf, "\n	],\n")
	fmt.Fprintf(buf, "	OldKey: %v,\n", p.OldKey)
	fmt.Fprintf(buf, "	OldValue: %v,\n", p.OldValue)
	fmt.Fprintf(buf, "	NewKey: %v,\n", p.NewKey)
	fmt.Fprintf(buf, "	NewValue: %v,\n", p.NewValue)
	fmt.Fprintf(buf, "	IsOld0: %v,\n", p.IsOld0)
	fmt.Fprintf(buf, "}\n")

	return buf.String()
}

// CircomVerifierProof defines the VerifierProof compatible with circom. Is the
// data of the proof that a certain leaf exists in the MerkleTree.
type CircomVerifierProof struct {
	Root     *Hash   `json:"root"`
	Siblings []*Hash `json:"siblings"`
	OldKey   *Hash   `json:"oldKey"`
	OldValue *Hash   `json:"oldValue"`
	IsOld0   bool    `json:"isOld0"`
	Key      *Hash   `json:"key"`
	Value    *Hash   `json:"value"`
	Fnc      int     `json:"fnc"` // 0: inclusion, 1: non inclusion
}

// GenerateCircomVerifierProof returns the CircomVerifierProof for a certain
// key in the MerkleTree.  If the rootKey is nil, the current merkletree root
// is used.
func (mt *MerkleTree) GenerateCircomVerifierProof(k *big.Int,
	rootKey *Hash) (*CircomVerifierProof, error) {
	cp, err := mt.GenerateSCVerifierProof(k, rootKey)
	if err != nil {
		return nil, err
	}
	cp.Siblings = CircomSiblingsFromSiblings(cp.Siblings, mt.maxLevels)
	return cp, nil
}

// GenerateSCVerifierProof returns the CircomVerifierProof for a certain key in
// the MerkleTree with the Siblings without the extra 0 needed at the circom
// circuits, which makes it straight forward to verifiy inside a Smart
// Contract.  If the rootKey is nil, the current merkletree root is used.
func (mt *MerkleTree) GenerateSCVerifierProof(k *big.Int,
	rootKey *Hash) (*CircomVerifierProof, error) {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	p, v, err := mt.GenerateProof(k, rootKey)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	var cp CircomVerifierProof
	cp.Root = rootKey
	cp.Siblings = p.AllSiblings()
	if p.NodeAux != nil {
		cp.OldKey = p.NodeAux.Key
		cp.OldValue = p.NodeAux.Value
	} else {
		cp.OldKey = &HashZero
		cp.OldValue = &HashZero
	}
	cp.Key = NewHashFromBigInt(k)
	cp.Value = NewHashFromBigInt(v)
	if p.Existence {
		cp.Fnc = 0 // inclusion
	} else {
		cp.Fnc = 1 // non inclusion
	}

	return &cp, nil
}

// GenerateProof generates the proof of existence (or non-existence) of an
// Entry's hash Index for a Merkle Tree given the root.
// If the rootKey is nil, the current merkletree root is used
func (mt *MerkleTree) GenerateProof(k *big.Int, rootKey *Hash) (*Proof,
	*big.Int, error) {
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
			return nil, nil, err
		}
		switch n.Type {
		case NodeTypeEmpty:
			return p, big.NewInt(0), nil
		case NodeTypeLeaf:
			if bytes.Equal(kHash[:], n.Entry[0][:]) {
				p.Existence = true
				return p, n.Entry[1].BigInt(), nil
			}
			// We found a leaf whose entry didn't match hIndex
			p.NodeAux = &NodeAux{Key: n.Entry[0], Value: n.Entry[1]}
			return p, n.Entry[1].BigInt(), nil
		case NodeTypeMiddle:
			if path[p.depth] {
				nextKey = n.ChildR
				siblingKey = n.ChildL
			} else {
				nextKey = n.ChildL
				siblingKey = n.ChildR
			}
		default:
			return nil, nil, ErrInvalidNodeFound
		}
		if !bytes.Equal(siblingKey[:], HashZero[:]) {
			SetBitBigEndian(p.notempties[:], uint(p.depth))
			p.Siblings = append(p.Siblings, siblingKey)
		}
	}
	return nil, nil, ErrKeyNotFound
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
// if rootKey is nil, it will get the current RootKey of the current state of
// the MerkleTree.  For each node, it calls the f function given in the
// parameters.  See some examples of the Walk function usage in the
// merkletree.go and merkletree_test.go
func (mt *MerkleTree) Walk(rootKey *Hash, f func(*Node)) error {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	err := mt.walk(rootKey, f)
	return err
}

// GraphViz uses Walk function to generate a string GraphViz representation of
// the tree and writes it to w
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
			fmt.Fprintf(w, "\"%v\" [style=filled];\n", k.String())
		case NodeTypeMiddle:
			lr := [2]string{n.ChildL.String(), n.ChildR.String()}
			emptyNodes := ""
			for i := range lr {
				if lr[i] == "0" {
					lr[i] = fmt.Sprintf("empty%v", cnt)
					emptyNodes += fmt.Sprintf("\"%v\" [style=dashed,label=0];\n", lr[i])
					cnt++
				}
			}
			fmt.Fprintf(w, "\"%v\" -> {\"%v\" \"%v\"}\n", k.String(), lr[0], lr[1])
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

// PrintGraphViz prints directly the GraphViz() output
func (mt *MerkleTree) PrintGraphViz(rootKey *Hash) error {
	if rootKey == nil {
		rootKey = mt.Root()
	}
	w := bytes.NewBufferString("")
	fmt.Fprintf(w,
		"--------\nGraphViz of the MerkleTree with RootKey "+rootKey.BigInt().String()+"\n")
	err := mt.GraphViz(w, nil)
	if err != nil {
		return err
	}
	fmt.Fprintf(w,
		"End of GraphViz of the MerkleTree with RootKey "+rootKey.BigInt().String()+"\n--------\n")

	fmt.Println(w)
	return nil
}

// DumpLeafs returns all the Leafs that exist under the given Root. If no Root
// is given (nil), it uses the current Root of the MerkleTree.
func (mt *MerkleTree) DumpLeafs(rootKey *Hash) ([]byte, error) {
	var b []byte
	err := mt.Walk(rootKey, func(n *Node) {
		if n.Type == NodeTypeLeaf {
			l := n.Entry[0].Bytes()
			r := n.Entry[1].Bytes()
			b = append(b, append(l[:], r[:]...)...)
		}
	})
	return b, err
}

// ImportDumpedLeafs parses and adds to the MerkleTree the dumped list of leafs
// from the DumpLeafs function.
func (mt *MerkleTree) ImportDumpedLeafs(b []byte) error {
	for i := 0; i < len(b); i += 64 {
		lr := b[i : i+64]
		lB, err := NewBigIntFromHashBytes(lr[:32])
		if err != nil {
			return err
		}
		rB, err := NewBigIntFromHashBytes(lr[32:])
		if err != nil {
			return err
		}
		err = mt.Add(lB, rB)
		if err != nil {
			return err
		}
	}
	return nil
}
