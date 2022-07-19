package datastore

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/jinzhu/copier"
	"github.com/stretchr/testify/require"
)

func setupTestDatastore(t *testing.T) *ProdDatastore {
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisDs, err := NewRedisCache(redisTestServer.Addr(), "")
	require.NoError(t, err)

	ds := NewProdDatastore(redisDs)
	require.NoError(t, err)

	return ds
}

func TestProdProposerValidatorRegistration(t *testing.T) {
	ds := setupTestDatastore(t)

	var reg1 types.SignedValidatorRegistration
	copier.Copy(&reg1, &common.ValidPayloadRegisterValidator)

	key := types.NewPubkeyHex(reg1.Message.Pubkey.String())

	// Set known validator and save registration
	err := ds.redis.SetKnownValidator(key, 1)
	require.NoError(t, err)
	err = ds.redis.SetValidatorRegistration(reg1)
	require.NoError(t, err)

	// Check if validator is known
	cnt, err := ds.RefreshKnownValidators()
	require.NoError(t, err)
	require.Equal(t, 1, cnt)
	require.True(t, ds.IsKnownValidator(key))

	// Copy the original registration
	var reg2 types.SignedValidatorRegistration
	copier.Copy(&reg2, &reg1)

	// // Ensure it's not updated with the same timestamp
	// reg2.Message.GasLimit = 7
	// ds.UpdateValidatorRegistration(reg2)
	// reg, err := ds.redis.GetValidatorRegistration(key)
	// require.NoError(t, err)
	// require.Equal(t, reg1.Message.GasLimit, reg.Message.GasLimit)

	// // Ensure it's not updated with an older timestamp
	// reg2.Message.Timestamp -= 1
	// ds.UpdateValidatorRegistration(reg2)
	// reg, err = ds.redis.GetValidatorRegistration(key)
	// require.NoError(t, err)
	// require.Equal(t, reg1.Message.GasLimit, reg.Message.GasLimit)

	// // Ensure it's updated with a newer timestamp
	// reg2.Message.Timestamp += 2
	// ds.UpdateValidatorRegistration(reg2)
	// reg, err = ds.redis.GetValidatorRegistration(key)
	// require.NoError(t, err)
	// require.Equal(t, reg2.Message.Timestamp, reg.Message.Timestamp)
	// require.NotEqual(t, reg1.Message.GasLimit, reg.Message.GasLimit)
	// require.Equal(t, reg2.Message.GasLimit, reg.Message.GasLimit)
}

// func TestRedisKnownValidators(t *testing.T) {
// 	cache := setupService(t)

// 	t.Run("Can save and get known validators", func(t *testing.T) {
// 		key1 := common.NewPubkeyHex("0x1a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
// 		key2 := common.NewPubkeyHex("0x2a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
// 		require.NoError(t, cache.SetKnownValidator(key1))
// 		require.NoError(t, cache.SetKnownValidator(key2))

// 		result, err := cache.IsKnownValidator(key1)
// 		require.NoError(t, err)
// 		require.True(t, result)

// 		knownVals, err := cache.GetKnownValidators()
// 		require.NoError(t, err)
// 		require.Equal(t, 2, len(knownVals))
// 		require.Contains(t, knownVals, key1)
// 		require.Contains(t, knownVals, key2)
// 	})
// }
