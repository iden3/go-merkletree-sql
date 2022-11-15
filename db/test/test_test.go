package test

//func TestMerkleTree_AddAndGetCircomProof_ErrExistKey(t *testing.T) {
//	store := memory.NewMemoryStorage()
//	tree, err := merkletree.NewMerkleTree(context.Background(), store, 10)
//	require.NoError(t, err)
//
//	err = tree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
//	require.NoError(t, err)
//
//	_, err = tree.AddAndGetCircomProof(context.Background(), big.NewInt(1), big.NewInt(20))
//	require.ErrorIs(t, err, merkletree.ErrEntryIndexAlreadyExists)
//}
//
//// Check old fields when node was deleted
//func TestMerkleTree_AddAndGetCircomProof_Delete(t *testing.T) {
//	store := memory.NewMemoryStorage()
//	tree, err := merkletree.NewMerkleTree(context.Background(), store, 10)
//	require.NoError(t, err)
//
//	err = tree.Add(context.Background(), big.NewInt(1), big.NewInt(1))
//	require.NoError(t, err)
//
//	err = tree.Add(context.Background(), big.NewInt(2), big.NewInt(1))
//	require.NoError(t, err)
//
//	err = tree.Delete(context.Background(), big.NewInt(1))
//	require.NoError(t, err)
//
//	proof, err := tree.AddAndGetCircomProof(context.Background(), big.NewInt(1), big.NewInt(20))
//	require.NoError(t, err)
//	fmt.Println(proof)
//}
//
//func TestDataRace(t *testing.T) {
//	store := memory.NewMemoryStorage()
//	source := []int64{0, 1, 2, 3, 4, 5}
//	tree, err := merkletree.NewMerkleTree(context.Background(), store, 4)
//	require.NoError(t, err)
//
//	wg := &sync.WaitGroup{}
//	wg.Add(len(source))
//
//	// getter
//	go func() {
//		tree.Get(context.Background(), big.NewInt(source[0]))
//		// time.Sleep(300 * time.Microsecond)
//	}()
//
//	for i := range source {
//		go func(inx int) {
//			defer wg.Done()
//			err := tree.Add(context.Background(), big.NewInt(source[inx]), big.NewInt(source[inx]))
//			require.NoError(t, err)
//		}(i)
//	}
//
//	wg.Wait()
//}
