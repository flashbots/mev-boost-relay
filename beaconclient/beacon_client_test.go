package beaconclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

const testPubKey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"

var errTest = errors.New("test error")

type testBackend struct {
	t               require.TestingT
	beaconInstances []*MockBeaconInstance
	beaconClient    IMultiBeaconClient
}

func newTestBackend(t require.TestingT, numBeaconNodes int) *testBackend {
	mockBeaconInstances := make([]*MockBeaconInstance, numBeaconNodes)
	beaconInstancesInterface := make([]IBeaconInstance, numBeaconNodes)
	for i := 0; i < numBeaconNodes; i++ {
		mockBeaconInstances[i] = NewMockBeaconInstance()
		beaconInstancesInterface[i] = mockBeaconInstances[i]
	}

	return &testBackend{
		t:               t,
		beaconInstances: mockBeaconInstances,
		beaconClient:    NewMultiBeaconClient(common.TestLog, beaconInstancesInterface),
	}
}

func TestBeaconInstance(t *testing.T) {
	r := mux.NewRouter()
	srv := httptest.NewServer(r)
	bc := NewProdBeaconInstance(common.TestLog, srv.URL)

	r.HandleFunc("/eth/v1/beacon/states/1/validators", func(w http.ResponseWriter, _ *http.Request) {
		resp := []byte(`{
  "execution_optimistic": false,
  "data": [
    {
      "index": "1",
      "balance": "1",
      "status": "active_ongoing",
      "validator": {
        "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
        "withdrawal_credentials": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
        "effective_balance": "1",
        "slashed": false,
        "activation_eligibility_epoch": "1",
        "activation_epoch": "1",
        "exit_epoch": "1",
        "withdrawable_epoch": "1"
      }
    }
  ]
}`)
		_, err := w.Write(resp)
		require.NoError(t, err)
	})

	vals, err := bc.FetchValidators(1)
	require.NoError(t, err)
	require.Equal(t, 1, len(vals))
	require.Contains(t, vals, types.PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"))
}

func TestGetSyncStatus(t *testing.T) {
	t.Run("returns status of highest head slot", func(t *testing.T) {
		syncStatuses := []*SyncStatusPayloadData{
			{
				HeadSlot:  3,
				IsSyncing: true,
			},
			{
				HeadSlot:  1,
				IsSyncing: false,
			},
			{
				HeadSlot:  2,
				IsSyncing: false,
			},
		}

		backend := newTestBackend(t, 3)
		for i := 0; i < len(backend.beaconInstances); i++ {
			backend.beaconInstances[i].MockSyncStatus = syncStatuses[i]
			backend.beaconInstances[i].ResponseDelay = 10 * time.Millisecond * time.Duration(i)
		}

		status, err := backend.beaconClient.BestSyncStatus()
		require.NoError(t, err)
		require.Equal(t, syncStatuses[1], status)
	})

	t.Run("returns status if at least one beacon node does not return error and is synced", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconInstances[0].MockSyncStatusErr = errTest
		status, err := backend.beaconClient.BestSyncStatus()
		require.NoError(t, err)
		require.NotNil(t, status)
	})

	t.Run("returns error if all beacon nodes return error or syncing", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconInstances[0].MockSyncStatusErr = errTest
		backend.beaconInstances[1].MockSyncStatus = &SyncStatusPayloadData{
			HeadSlot:  1,
			IsSyncing: true,
		}
		status, err := backend.beaconClient.BestSyncStatus()
		require.Equal(t, ErrBeaconNodeSyncing, err)
		require.Nil(t, status)
	})
}

func TestUpdateProposerDuties(t *testing.T) {
	t.Run("returns err if all of the beacon nodes return error", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconInstances[0].MockProposerDutiesErr = errTest
		backend.beaconInstances[1].MockProposerDutiesErr = errTest
		status, err := backend.beaconClient.GetProposerDuties(1)
		require.Error(t, err)
		require.Nil(t, status)
	})

	t.Run("get propose duties from the first beacon node that does not error", func(t *testing.T) {
		mockResponse := &ProposerDutiesResponse{
			Data: []ProposerDutiesResponseData{
				{
					Pubkey: testPubKey,
					Slot:   2,
				},
			},
		}

		backend := newTestBackend(t, 3)
		backend.beaconInstances[0].MockProposerDutiesErr = errTest
		backend.beaconInstances[1].ResponseDelay = 10 * time.Millisecond
		backend.beaconInstances[1].MockProposerDuties = mockResponse

		duties, err := backend.beaconClient.GetProposerDuties(2)
		require.NoError(t, err)
		require.Equal(t, *mockResponse, *duties)
	})
}

func TestFetchValidators(t *testing.T) {
	t.Run("returns err if all of the beacon nodes return error", func(t *testing.T) {
		backend := newTestBackend(t, 2)
		backend.beaconInstances[0].MockFetchValidatorsErr = errTest
		backend.beaconInstances[1].MockFetchValidatorsErr = errTest
		status, err := backend.beaconClient.FetchValidators(1)
		require.Error(t, err)
		require.Nil(t, status)
	})

	t.Run("get validator set first from beacon node that did not err", func(t *testing.T) {
		entry := ValidatorResponseEntry{
			Validator: ValidatorResponseValidatorData{
				Pubkey: testPubKey,
			},
			Index:   0,
			Balance: "0",
			Status:  "",
		}

		backend := newTestBackend(t, 3)
		backend.beaconInstances[0].MockFetchValidatorsErr = errTest
		backend.beaconInstances[1].AddValidator(entry)
		backend.beaconInstances[2].MockFetchValidatorsErr = errTest

		validators, err := backend.beaconClient.FetchValidators(1)
		require.NoError(t, err)
		require.Equal(t, 1, len(validators))
		require.Contains(t, validators, types.PubkeyHex(testPubKey))

		backend.beaconInstances[0].MockFetchValidatorsErr = nil
		backend.beaconInstances[1].SetValidators(make(map[types.PubkeyHex]ValidatorResponseEntry))
		backend.beaconInstances[2].MockFetchValidatorsErr = nil
		backend.beaconInstances[2].AddValidator(entry)

		t.Log(backend.beaconInstances[1].NumValidators())
		validators, err = backend.beaconClient.FetchValidators(1)
		require.NoError(t, err)
		require.Equal(t, 0, len(validators))
	})
}
