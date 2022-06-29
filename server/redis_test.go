package server

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

// var redisTestServer *miniredis.Miniredis

func setupService(t *testing.T) Datastore {
	var err error
	// if redisTestServer != nil {
	// 	redisTestServer.Close()
	// }

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisService, err := NewRedisService(redisTestServer.Addr())
	require.NoError(t, err)

	return redisService
}

func TestRedisService(t *testing.T) {
	cache := setupService(t)

	t.Run("Can save and get validator registration from cache", func(t *testing.T) {
		key := validPayloadRegisterValidator.Message.Pubkey
		value := validPayloadRegisterValidator
		cache.SaveValidatorRegistration(value)
		result, err := cache.GetValidatorRegistration(key)
		require.NoError(t, err)
		require.Equal(t, *result, value)
	})

	t.Run("Returns nil if validator registration is not in cache", func(t *testing.T) {
		key := types.PublicKey{}
		result, err := cache.GetValidatorRegistration(key)
		require.NoError(t, err)
		require.Nil(t, result)
	})
}
