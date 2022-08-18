package housekeeper

import (
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

const (
	testPubKey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
)

var errTest = errors.New("test error")

type testBackend struct {
	t             require.TestingT
	housekeeper   *Housekeeper
	beaconClients []*beaconclient.MockBeaconClient
	datastore     *datastore.Datastore
	redis         *datastore.RedisCache
}

func newTestBackend(t require.TestingT, numBeaconNodes int) *testBackend {
	mockBeaconClients := make([]*beaconclient.MockBeaconClient, numBeaconNodes)
	mockBeaconClientsInterface := make([]beaconclient.BeaconNodeClient, numBeaconNodes)
	for i := 0; i < numBeaconNodes; i++ {
		mockBeaconClients[i] = beaconclient.NewMockBeaconClient()
		mockBeaconClientsInterface[i] = mockBeaconClients[i]
	}

	redisClient, err := miniredis.Run()
	require.NoError(t, err)

	redisCache, err := datastore.NewRedisCache(redisClient.Addr(), "")
	require.NoError(t, err)

	db := database.MockDB{}

	ds, err := datastore.NewDatastore(common.TestLog, redisCache, db)
	require.NoError(t, err)

	opts := &HousekeeperOpts{
		Log:           common.TestLog,
		BeaconClients: mockBeaconClientsInterface,
		Datastore:     ds,
		Redis:         redisCache,
	}

	housekeeper := NewHousekeeper(opts)

	backend := testBackend{
		t:             t,
		housekeeper:   housekeeper,
		beaconClients: mockBeaconClients,
		datastore:     ds,
		redis:         redisCache,
	}
	return &backend
}

func TestGetSyncStatus(t *testing.T) {
	t.Run("returns status of highest head slot", func(t *testing.T) {
		lowerSyncStatus := &beaconclient.SyncStatusPayloadData{
			HeadSlot:  1,
			IsSyncing: false,
		}
		higherSyncStatus := &beaconclient.SyncStatusPayloadData{
			HeadSlot:  2,
			IsSyncing: false,
		}
		backend := newTestBackend(t, 2)
		backend.beaconClients[0].MockSyncStatus = lowerSyncStatus
		backend.beaconClients[1].MockSyncStatus = higherSyncStatus
		status, err := backend.housekeeper.getBestSyncStatus()
		require.NoError(t, err)
		require.Equal(t, uint64(2), status.HeadSlot)
	})

	t.Run("returns status if at least one beacon node does not return error and is synced", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconClients[0].MockSyncStatusErr = errTest
		status, err := backend.housekeeper.getBestSyncStatus()
		require.NoError(t, err)
		require.NotNil(t, status)
	})

	t.Run("returns error if all beacon nodes return error or syncing", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconClients[0].MockSyncStatusErr = errTest
		backend.beaconClients[1].MockSyncStatus = &beaconclient.SyncStatusPayloadData{
			HeadSlot:  1,
			IsSyncing: true,
		}
		status, err := backend.housekeeper.getBestSyncStatus()
		require.Equal(t, ErrBeaconNodeSyncing, err)
		require.Nil(t, status)
	})
}

func TestUpdateProposerDuties(t *testing.T) {
	t.Run("returns nil if all of the beacon nodes return error", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconClients[0].MockProposerDutiesErr = errTest
		backend.beaconClients[1].MockProposerDutiesErr = errTest
		status := backend.housekeeper.getProposerDuties(1)
		require.Nil(t, status)
	})

	t.Run("get propose duties from the response that returns first", func(t *testing.T) {
		mockResponse := &beaconclient.ProposerDutiesResponse{
			Data: []beaconclient.ProposerDutiesResponseData{
				{
					Pubkey: testPubKey,
					Slot:   2,
				},
			},
		}

		backend := newTestBackend(t, 3)
		backend.beaconClients[0].ResponseDelay = 10 * time.Millisecond
		backend.beaconClients[1].ResponseDelay = 10 * time.Millisecond
		backend.beaconClients[2].MockProposerDuties = mockResponse

		duties := backend.housekeeper.getProposerDuties(2)
		require.Equal(t, *mockResponse, *duties)
	})
}

func TestFetchValidators(t *testing.T) {
	t.Run("returns nil if all of the beacon nodes return error", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconClients[0].MockFetchValidatorsErr = errTest
		backend.beaconClients[1].MockFetchValidatorsErr = errTest
		status := backend.housekeeper.fetchValidators()
		require.Nil(t, status)
	})

	t.Run("get validator set from the response that returns first", func(t *testing.T) {
		entry := beaconclient.ValidatorResponseEntry{
			Validator: beaconclient.ValidatorResponseValidatorData{
				Pubkey: testPubKey,
			},
			Index:   0,
			Balance: "0",
			Status:  "synced",
		}

		backend := newTestBackend(t, 3)
		backend.beaconClients[0].ResponseDelay = 10 * time.Millisecond
		backend.beaconClients[1].ResponseDelay = 10 * time.Millisecond
		backend.beaconClients[2].AddValidator(entry)

		validators := backend.housekeeper.fetchValidators()
		require.Equal(t, 1, len(validators))
		require.Contains(t, validators, types.PubkeyHex(testPubKey))
	})
}
