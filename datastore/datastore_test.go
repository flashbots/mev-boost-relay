package datastore

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/jinzhu/copier"
	"github.com/stretchr/testify/require"
)

func setupTestDatastore(t *testing.T) *Datastore {
	t.Helper()
	var err error

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisDs, err := NewRedisCache(redisTestServer.Addr(), "", "")
	require.NoError(t, err)

	// TODO: add support for testing datastore with memcached enabled
	ds, err := NewDatastore(common.TestLog, redisDs, nil, database.MockDB{})

	require.NoError(t, err)

	// we should not panic when fetching execution payload response, even when memcached is nil
	_, err = ds.GetGetPayloadResponse(0, "foo", "bar")
	require.NoError(t, err)

	return ds
}

func TestProdProposerValidatorRegistration(t *testing.T) {
	ds := setupTestDatastore(t)

	var reg1 types.SignedValidatorRegistration
	err := copier.Copy(&reg1, &common.ValidPayloadRegisterValidator)
	require.NoError(t, err)

	key := types.NewPubkeyHex(reg1.Message.Pubkey.String())

	// Set known validator and save registration
	err = ds.redis.SetKnownValidator(key, 1)
	require.NoError(t, err)

	// Check if validator is known
	cnt, err := ds.RefreshKnownValidators()
	require.NoError(t, err)
	require.Equal(t, 1, cnt)
	require.True(t, ds.IsKnownValidator(key))

	// Copy the original registration
	var reg2 types.SignedValidatorRegistration
	err = copier.Copy(&reg2, &reg1)
	require.NoError(t, err)
}
