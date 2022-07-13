package datastore

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func setupTestRedis(t *testing.T) *RedisCache {
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisService, err := NewRedisCache(redisTestServer.Addr())
	require.NoError(t, err)

	return redisService
}

func TestRedisValidatorRegistration(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get validator registration from cache", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator
		cache.SetValidatorRegistration(value)
		result, err := cache.GetValidatorRegistration(key.PubkeyHex())
		require.NoError(t, err)
		require.Equal(t, *result, value)
	})

	t.Run("Returns nil if validator registration is not in cache", func(t *testing.T) {
		key := types.PublicKey{}
		result, err := cache.GetValidatorRegistration(key.PubkeyHex())
		require.NoError(t, err)
		require.Nil(t, result)
	})
}

func TestRedisKnownValidators(t *testing.T) {
	cache := setupTestRedis(t)

	t.Run("Can save and get known validators", func(t *testing.T) {
		key1 := types.NewPubkeyHex("0x1a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
		key2 := types.NewPubkeyHex("0x2a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
		require.NoError(t, cache.SetKnownValidator(key1, 1))
		require.NoError(t, cache.SetKnownValidator(key2, 2))

		knownVals, err := cache.GetKnownValidators()
		require.NoError(t, err)
		require.Equal(t, 2, len(knownVals))
		require.Contains(t, knownVals, key1)
		require.Contains(t, knownVals, key2)
	})

	// t.Run("Can save multiple known validators", func(t *testing.T) {
	// 	key1 := types.NewPubkeyHex("0x1a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
	// 	key2 := types.NewPubkeyHex("0x2a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249")
	// 	keys := []types.PubkeyHex{key1, key2}
	// 	require.NoError(t, cache.SetKnownValidators(keys))

	// 	knownVals, err := cache.GetKnownValidators()
	// 	require.NoError(t, err)
	// 	require.Equal(t, 2, len(knownVals))
	// 	require.Contains(t, knownVals, key1)
	// 	require.Contains(t, knownVals, key2)
	// })
}
