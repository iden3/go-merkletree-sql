package merkletree

import (
	"errors"
	"math/big"
	"sync"

	"github.com/iden3/go-iden3-core/common"
	"github.com/iden3/go-iden3-core/db"
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

	rootNodeValue = []byte("currentroot")
	HashZero      = Hash{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
)

type Hash [32]byte

func (h Hash) String() string {
	return new(big.Int).SetBytes(h[:]).String()
}
func (h *Hash) BigInt() *big.Int {
	return new(big.Int).SetBytes(common.SwapEndianness(h[:]))
}

func NewHashFromBigInt(b *big.Int) *Hash {
	r := &Hash{}
	copy(r[:], common.SwapEndianness(b.Bytes()))
	return r
}

type MerkleTree struct {
	sync.RWMutex
	db        db.Storage
	rootKey   *Hash
	writable  bool
	maxLevels int
}

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

func (mt *MerkleTree) Root() *Hash {
	return mt.rootKey
}
