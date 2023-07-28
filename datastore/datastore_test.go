package datastore

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/stretchr/testify/require"
)

func setupTestDatastore(t *testing.T, mockDB *database.MockDB) *Datastore {
	t.Helper()

	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisDs, err := NewRedisCache("", redisTestServer.Addr(), "")
	require.NoError(t, err)

	ds, err := NewDatastore(redisDs, nil, mockDB)
	require.NoError(t, err)

	return ds
}

func TestGetPayloadFailure(t *testing.T) {
	ds := setupTestDatastore(t, &database.MockDB{})
	_, err := ds.GetGetPayloadResponse(common.TestLog, 1, "a", "b")
	require.Error(t, ErrExecutionPayloadNotFound, err)
}

func TestGetPayloadDatabaseFallback(t *testing.T) {
	filename := "../testdata/executionPayloadCapella_Goerli.json.gz"
	payloadBytes := common.LoadGzippedBytes(t, filename)

	// prepare mock database with execution payload entry
	mockDB := &database.MockDB{
		ExecPayloads: map[string]*database.ExecutionPayloadEntry{
			"1-a-b": {
				Version: common.ForkVersionStringCapella,
				Payload: string(payloadBytes),
			},
		},
	}
	ds := setupTestDatastore(t, mockDB)
	payload, err := ds.GetGetPayloadResponse(common.TestLog, 1, "a", "b")
	require.NoError(t, err)
	require.Equal(t, "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121", payload.Capella.BlockHash.String())
}
