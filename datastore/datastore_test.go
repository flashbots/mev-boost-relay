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
	require.ErrorIs(t, ErrExecutionPayloadNotFound, err)
}

func TestGetPayloadDatabaseFallback(t *testing.T) {
	testCases := []struct {
		description string
		filename    string
		version     string
		blockHash   string
	}{
		{
			description: "Good Capella Payload",
			filename:    "../testdata/executionPayloadCapella_Goerli.json.gz",
			version:     common.ForkVersionStringCapella,
			blockHash:   "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121",
		},
		{
			description: "Good Deneb Payload",
			filename:    "../testdata/executionPayloadAndBlobsBundleDeneb_Goerli.json.gz",
			version:     common.ForkVersionStringDeneb,
			blockHash:   "0xbd1ae4f7edb2315d2df70a8d9881fab8d6763fb1c00533ae729050928c38d05a",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.description, func(t *testing.T) {
			payloadBytes := common.LoadGzippedBytes(t, testCase.filename)

			// prepare mock database with execution payload entry
			mockDB := &database.MockDB{
				ExecPayloads: map[string]*database.ExecutionPayloadEntry{
					"1-a-b": {
						Version: testCase.version,
						Payload: string(payloadBytes),
					},
				},
			}
			ds := setupTestDatastore(t, mockDB)
			payload, err := ds.GetGetPayloadResponse(common.TestLog, 1, "a", "b")
			require.NoError(t, err)
			blockHash, err := payload.BlockHash()
			require.NoError(t, err)
			require.Equal(t, testCase.blockHash, blockHash.String())
		})
	}
}
