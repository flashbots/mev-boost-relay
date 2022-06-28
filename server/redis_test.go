package server

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

var redisTestServer *miniredis.Miniredis

func setupService(t *testing.T) Datastore {
	var err error
	if redisTestServer != nil {
		redisTestServer.Close()
	}

	redisTestServer, err := miniredis.Run()
	if err != nil {
		t.Error("error starting miniredis", err)
	}

	redisService, err := NewRedisService(redisTestServer.Addr(), common.TestLog)
	if err != nil {
		t.Error("error creating new redis service", err)
	}
	return redisService
}

func TestRedisService(t *testing.T) {
	cache := setupService(t)

	t.Run("Can save and get validator registration from cache", func(t *testing.T) {
		key := common.ValidPayloadRegisterValidator.Message.Pubkey
		value := common.ValidPayloadRegisterValidator
		cache.SaveValidatorRegistration(value)
		result := cache.GetValidatorRegistration(key)
		require.Equal(t, *result, value)
	})

	t.Run("Returns nil if validator registration is not in cache", func(t *testing.T) {
		key := types.PublicKey{}
		result := cache.GetValidatorRegistration(key)
		require.Nil(t, result)
	})
}
