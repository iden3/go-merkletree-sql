package memory

import (
	"github.com/iden3/go-merkletree"
	"testing"

	"github.com/iden3/go-merkletree/db/test"
	"github.com/stretchr/testify/require"
)

func TestMemoryStorageInterface(t *testing.T) {
	var db merkletree.Storage //nolint:gosimple

	db = NewMemoryStorage()
	require.NotNil(t, db)
}

func TestMemory(t *testing.T) {
	test.TestReturnKnownErrIfNotExists(t, NewMemoryStorage())
	test.TestStorageInsertGet(t, NewMemoryStorage())
	test.TestStorageWithPrefix(t, NewMemoryStorage())
	test.TestConcatTx(t, NewMemoryStorage())
	test.TestList(t, NewMemoryStorage())
	test.TestIterate(t, NewMemoryStorage())

	test.TestNewTree(t, NewMemoryStorage())
	test.TestAddDifferentOrder(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestAddRepeatedIndex(t, NewMemoryStorage())
	test.TestGet(t, NewMemoryStorage())
	test.TestUpdate(t, NewMemoryStorage())
	test.TestUpdate2(t, NewMemoryStorage())
	test.TestGenerateAndVerifyProof128(t, NewMemoryStorage())
	test.TestTreeLimit(t, NewMemoryStorage())
	test.TestSiblingsFromProof(t, NewMemoryStorage())
	test.TestVerifyProofCases(t, NewMemoryStorage())
	test.TestVerifyProofFalse(t, NewMemoryStorage())
	test.TestGraphViz(t, NewMemoryStorage())
	test.TestDelete(t, NewMemoryStorage())
	test.TestDelete2(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestDelete3(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestDelete4(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestDelete5(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestDeleteNonExistingKeys(t, NewMemoryStorage())
	test.TestDumpLeafsImportLeafs(t, NewMemoryStorage(), NewMemoryStorage())
	test.TestAddAndGetCircomProof(t, NewMemoryStorage())
	test.TestUpdateCircomProcessorProof(t, NewMemoryStorage())
	test.TestSmtVerifier(t, NewMemoryStorage())
	test.TestTypesMarshalers(t, NewMemoryStorage())

}
