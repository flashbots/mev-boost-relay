package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

var builderSigningDomain = types.Domain([32]byte{0, 0, 0, 1, 245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169})

type testBackend struct {
	t         require.TestingT
	relay     *RelayAPI
	datastore *datastore.Datastore
	redis     *datastore.RedisCache
}

func newTestBackend(t require.TestingT, numBeaconNodes int) *testBackend {
	redisClient, err := miniredis.Run()
	require.NoError(t, err)

	redisCache, err := datastore.NewRedisCache("", redisClient.Addr(), "")
	require.NoError(t, err)

	db := database.MockDB{}

	ds, err := datastore.NewDatastore(redisCache, nil, db)
	require.NoError(t, err)

	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)

	mainnetDetails, err := common.NewEthNetworkDetails(common.EthNetworkMainnet)
	require.NoError(t, err)

	opts := RelayAPIOpts{
		Log:             common.TestLog,
		ListenAddr:      "localhost:12345",
		BeaconClient:    &beaconclient.MultiBeaconClient{},
		Datastore:       ds,
		Redis:           redisCache,
		DB:              db,
		EthNetDetails:   *mainnetDetails,
		SecretKey:       sk,
		ProposerAPI:     true,
		BlockBuilderAPI: true,
		DataAPI:         true,
		InternalAPI:     true,
	}

	relay, err := NewRelayAPI(opts)
	require.NoError(t, err)

	relay.genesisInfo = &beaconclient.GetGenesisResponse{
		Data: beaconclient.GetGenesisResponseData{
			GenesisTime: 1606824023,
		},
	}

	backend := testBackend{
		t:         t,
		relay:     relay,
		datastore: ds,
		redis:     redisCache,
	}
	return &backend
}

func (be *testBackend) request(method, path string, payload any) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, bytes.NewReader(nil))
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		require.NoError(be.t, err2)
		req, err = http.NewRequest(method, path, bytes.NewReader(payloadBytes))
	}
	require.NoError(be.t, err)

	// lfg
	rr := httptest.NewRecorder()
	be.relay.getRouter().ServeHTTP(rr, req)
	return rr
}

func (be *testBackend) requestWithUA(method, path, userAgent string, payload any) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, bytes.NewReader(nil))
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		require.NoError(be.t, err2)
		req, err = http.NewRequest(method, path, bytes.NewReader(payloadBytes))
	}
	req.Header.Set("User-Agent", userAgent)

	require.NoError(be.t, err)
	rr := httptest.NewRecorder()
	be.relay.getRouter().ServeHTTP(rr, req)
	return rr
}

// func generateSignedValidatorRegistration(sk *bls.SecretKey, feeRecipient types.Address, timestamp uint64) (*types.SignedValidatorRegistration, error) {
// 	var err error
// 	if sk == nil {
// 		sk, _, err = bls.GenerateNewKeypair()
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

// 	blsPubKey, _ := bls.PublicKeyFromSecretKey(sk)

// 	var pubKey types.PublicKey
// 	err = pubKey.FromSlice(bls.PublicKeyToBytes(blsPubKey))
// 	if err != nil {
// 		return nil, err
// 	}
// 	msg := &types.RegisterValidatorRequestMessage{
// 		FeeRecipient: feeRecipient,
// 		Timestamp:    timestamp,
// 		Pubkey:       pubKey,
// 		GasLimit:     278234191203,
// 	}

// 	sig, err := types.SignMessage(msg, builderSigningDomain, sk)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &types.SignedValidatorRegistration{
// 		Message:   msg,
// 		Signature: sig,
// 	}, nil
// }

func TestWebserver(t *testing.T) {
	t.Run("errors when webserver is already existing", func(t *testing.T) {
		backend := newTestBackend(t, 1)
		backend.relay.srvStarted.Store(true)
		err := backend.relay.StartServer()
		require.Error(t, err)
	})
}

func TestWebserverRootHandler(t *testing.T) {
	backend := newTestBackend(t, 1)
	rr := backend.request(http.MethodGet, "/", nil)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestStatus(t *testing.T) {
	backend := newTestBackend(t, 1)
	path := "/eth/v1/builder/status"
	rr := backend.request(http.MethodGet, path, common.ValidPayloadRegisterValidator)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestLivez(t *testing.T) {
	backend := newTestBackend(t, 1)
	path := "/livez"
	rr := backend.request(http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "{\"message\":\"live\"}\n", rr.Body.String())
}

func TestRegisterValidator(t *testing.T) {
	path := "/eth/v1/builder/validators"

	// t.Run("Normal function", func(t *testing.T) {
	// 	backend := newTestBackend(t, 1)
	// 	pubkeyHex := common.ValidPayloadRegisterValidator.Message.Pubkey.PubkeyHex()
	// 	index := uint64(17)
	// 	err := backend.redis.SetKnownValidator(pubkeyHex, index)
	// 	require.NoError(t, err)

	// 	// Update datastore
	// 	_, err = backend.datastore.RefreshKnownValidators()
	// 	require.NoError(t, err)
	// 	require.True(t, backend.datastore.IsKnownValidator(pubkeyHex))
	// 	pkH, ok := backend.datastore.GetKnownValidatorPubkeyByIndex(index)
	// 	require.True(t, ok)
	// 	require.Equal(t, pubkeyHex, pkH)

	// 	payload := []types.SignedValidatorRegistration{common.ValidPayloadRegisterValidator}
	// 	rr := backend.request(http.MethodPost, path, payload)
	// 	require.Equal(t, http.StatusOK, rr.Code)
	// 	time.Sleep(20 * time.Millisecond) // registrations are processed asynchronously

	// 	isKnown := backend.datastore.IsKnownValidator(pubkeyHex)
	// 	require.True(t, isKnown)
	// })

	t.Run("not a known validator", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		rr := backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{common.ValidPayloadRegisterValidator})
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	// t.Run("Reject registration for >10sec into the future", func(t *testing.T) {
	// 	backend := newTestBackend(t, 1)

	// 	// Allow +10 sec
	// 	td := uint64(time.Now().Unix())
	// 	payload, err := generateSignedValidatorRegistration(nil, types.Address{1}, td+10)
	// 	require.NoError(t, err)
	// 	err = backend.redis.SetKnownValidator(payload.Message.Pubkey.PubkeyHex(), 1)
	// 	require.NoError(t, err)
	// 	_, err = backend.datastore.RefreshKnownValidators()
	// 	require.NoError(t, err)

	// 	rr := backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{*payload})
	// 	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 	// Disallow +11 sec
	// 	td = uint64(time.Now().Unix())
	// 	payload, err = generateSignedValidatorRegistration(nil, types.Address{1}, td+12)
	// 	require.NoError(t, err)
	// 	err = backend.redis.SetKnownValidator(payload.Message.Pubkey.PubkeyHex(), 1)
	// 	require.NoError(t, err)
	// 	_, err = backend.datastore.RefreshKnownValidators()
	// 	require.NoError(t, err)

	// 	rr = backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{*payload})
	// 	require.Equal(t, http.StatusBadRequest, rr.Code)
	// 	require.Contains(t, rr.Body.String(), "timestamp too far in the future")
	// })
}

func TestGetHeader(t *testing.T) {
	// Setup backend with headSlot and genesisTime
	backend := newTestBackend(t, 1)
	backend.relay.genesisInfo = &beaconclient.GetGenesisResponse{
		Data: beaconclient.GetGenesisResponseData{
			GenesisTime: uint64(time.Now().UTC().Unix()),
		},
	}

	// request params
	slot := uint64(2)
	backend.relay.headSlot.Store(slot)
	parentHash := "0x13e606c7b3d1faad7e83503ce3dedce4c6bb89b0c28ffb240d713c7b110b9747"
	proposerPubkey := "0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792"
	builderPubkey := "0xfa1ed37c3553d0ce1e9349b2c5063cf6e394d231c8d3e0df75e9462257c081543086109ffddaacc0aa76f33dc9661c83"
	bidValue := big.NewInt(99)
	trace := &common.BidTraceV2{
		BidTrace: v1.BidTrace{
			Value: uint256.MustFromBig(bidValue),
		},
	}

	// request path
	path := fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHash, proposerPubkey)

	// Create a bid
	opts := common.CreateTestBlockSubmissionOpts{
		Slot:           slot,
		ParentHash:     parentHash,
		ProposerPubkey: proposerPubkey,
	}
	payload, getPayloadResp, getHeaderResp := common.CreateTestBlockSubmission(t, builderPubkey, bidValue, &opts)
	_, err := backend.redis.SaveBidAndUpdateTopBid(context.Background(), backend.redis.NewPipeline(), trace, payload, getPayloadResp, getHeaderResp, time.Now(), false, nil)
	require.NoError(t, err)

	// Check 1: regular request works and returns a bid
	rr := backend.request(http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	resp := common.GetHeaderResponse{}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, bidValue.String(), resp.Value().String())

	// Check 2: Request returns 204 if sending a filtered user agent
	rr = backend.requestWithUA(http.MethodGet, path, "mev-boost/v1.5.0 Go-http-client/1.1", nil)
	require.Equal(t, http.StatusNoContent, rr.Code)
}

func TestBuilderApiGetValidators(t *testing.T) {
	path := "/relay/v1/builder/validators"

	backend := newTestBackend(t, 1)
	duties := []common.BuilderGetValidatorsResponseEntry{
		{
			Slot:  1,
			Entry: &common.ValidPayloadRegisterValidator,
		},
	}
	responseBytes, err := json.Marshal(duties)
	require.NoError(t, err)
	backend.relay.proposerDutiesResponse = &responseBytes

	rr := backend.request(http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	resp := []common.BuilderGetValidatorsResponseEntry{}
	err = json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp))
	require.Equal(t, uint64(1), resp[0].Slot)
	require.Equal(t, common.ValidPayloadRegisterValidator, *resp[0].Entry)
}

func TestDataApiGetDataProposerPayloadDelivered(t *testing.T) {
	path := "/relay/v1/data/bidtraces/proposer_payload_delivered"

	t.Run("Accept valid block_hash", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validBlockHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		rr := backend.request(http.MethodGet, path+"?block_hash="+validBlockHash, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject invalid block_hash", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		invalidBlockHashes := []string{
			// One character too long.
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			// One character too short.
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			// Missing the 0x prefix.
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			// Has an invalid hex character ('z' at the end).
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz",
		}

		for _, invalidBlockHash := range invalidBlockHashes {
			rr := backend.request(http.MethodGet, path+"?block_hash="+invalidBlockHash, nil)
			t.Log(invalidBlockHash)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "invalid block_hash argument")
		}
	})
}

func TestDataApiGetBuilderBlocksReceived(t *testing.T) {
	path := "/relay/v1/data/bidtraces/builder_blocks_received"

	t.Run("Reject requests with cursor", func(t *testing.T) {
		backend := newTestBackend(t, 1)
		rr := backend.request(http.MethodGet, path+"?cursor=1", nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "cursor argument not supported")
	})

	t.Run("Accept valid slot", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validSlot := uint64(2)
		validSlotPath := fmt.Sprintf("%s?slot=%d", path, validSlot)
		rr := backend.request(http.MethodGet, validSlotPath, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Accept valid slot", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validSlot := uint64(2)
		validSlotPath := fmt.Sprintf("%s?slot=%d", path, validSlot)
		rr := backend.request(http.MethodGet, validSlotPath, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject invalid slot", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		invalidSlots := []string{
			"-1",
			"1.1",
		}

		for _, invalidSlot := range invalidSlots {
			invalidSlotPath := fmt.Sprintf("%s?slot=%s", path, invalidSlot)
			rr := backend.request(http.MethodGet, invalidSlotPath, nil)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "invalid slot argument")
		}
	})

	t.Run("Accept valid block_hash", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validBlockHash := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		rr := backend.request(http.MethodGet, path+"?block_hash="+validBlockHash, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject invalid block_hash", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		invalidBlockHashes := []string{
			// One character too long.
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
			// One character too short.
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			// Missing the 0x prefix.
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			// Has an invalid hex character ('z' at the end).
			"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaz",
		}

		for _, invalidBlockHash := range invalidBlockHashes {
			rr := backend.request(http.MethodGet, path+"?block_hash="+invalidBlockHash, nil)
			t.Log(invalidBlockHash)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "invalid block_hash argument")
		}
	})

	t.Run("Accept valid block_number", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validBlockNumber := uint64(2)
		validBlockNumberPath := fmt.Sprintf("%s?block_number=%d", path, validBlockNumber)
		rr := backend.request(http.MethodGet, validBlockNumberPath, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject invalid block_number", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		invalidBlockNumbers := []string{
			"-1",
			"1.1",
		}

		for _, invalidBlockNumber := range invalidBlockNumbers {
			invalidBlockNumberPath := fmt.Sprintf("%s?block_number=%s", path, invalidBlockNumber)
			rr := backend.request(http.MethodGet, invalidBlockNumberPath, nil)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "invalid block_number argument")
		}
	})

	t.Run("Accept valid builder_pubkey", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		validBuilderPubkey := "0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792"
		rr := backend.request(http.MethodGet, path+"?builder_pubkey="+validBuilderPubkey, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject invalid builder_pubkey", func(t *testing.T) {
		backend := newTestBackend(t, 1)

		invalidBuilderPubkeys := []string{
			// One character too long.
			"0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b908907921",
			// One character too short.
			"0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b9089079",
			// Missing the 0x prefix.
			"6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b90890792",
			// Has an invalid hex character ('z' at the end).
			"0x6ae5932d1e248d987d51b58665b81848814202d7b23b343d20f2a167d12f07dcb01ca41c42fdd60b7fca9c4b9089079z",
		}

		for _, invalidBuilderPubkey := range invalidBuilderPubkeys {
			rr := backend.request(http.MethodGet, path+"?builder_pubkey="+invalidBuilderPubkey, nil)
			t.Log(invalidBuilderPubkey)
			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), "invalid builder_pubkey argument")
		}
	})

	t.Run("Reject no slot or block_hash or block_number or builder_pubkey", func(t *testing.T) {
		backend := newTestBackend(t, 1)
		rr := backend.request(http.MethodGet, path, nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "need to query for specific slot or block_hash or block_number or builder_pubkey")
	})

	t.Run("Accept valid limit", func(t *testing.T) {
		backend := newTestBackend(t, 1)
		blockNumber := uint64(1)
		limit := uint64(1)
		limitPath := fmt.Sprintf("%s?block_number=%d&limit=%d", path, blockNumber, limit)
		rr := backend.request(http.MethodGet, limitPath, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})

	t.Run("Reject above max limit", func(t *testing.T) {
		backend := newTestBackend(t, 1)
		blockNumber := uint64(1)
		maximumLimit := uint64(500)
		oneAboveMaxLimit := maximumLimit + 1
		limitPath := fmt.Sprintf("%s?block_number=%d&limit=%d", path, blockNumber, oneAboveMaxLimit)
		rr := backend.request(http.MethodGet, limitPath, nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), fmt.Sprintf("maximum limit is %d", maximumLimit))
	})
}
