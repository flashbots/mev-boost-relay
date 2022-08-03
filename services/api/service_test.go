package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

var (
	genesisForkVersionHex = "0x00000000"
	builderSigningDomain  = types.Domain([32]byte{0, 0, 0, 1, 245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169})
)

type testBackend struct {
	t            require.TestingT
	relay        *RelayAPI
	beaconClient *beaconclient.MockBeaconClient
	datastore    *datastore.Datastore
	redis        *datastore.RedisCache
}

func newTestBackend(t require.TestingT) *testBackend {
	bc := beaconclient.NewMockBeaconClient()

	redisClient, err := miniredis.Run()
	require.NoError(t, err)

	redisCache, err := datastore.NewRedisCache(redisClient.Addr(), "")
	require.NoError(t, err)

	db := database.MockDB{}

	ds, err := datastore.NewDatastore(common.TestLog, redisCache, db)
	require.NoError(t, err)

	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)

	opts := RelayAPIOpts{
		Log:          common.TestLog,
		ListenAddr:   "localhost:12345",
		BeaconClient: bc,
		Datastore:    ds,
		Redis:        redisCache,
		DB:           db,
		EthNetDetails: common.EthNetworkDetails{
			GenesisForkVersionHex:   genesisForkVersionHex,
			BellatrixForkVersionHex: "0x00000000",
		},
		SecretKey: sk,
	}

	relay, err := NewRelayAPI(opts)
	require.NoError(t, err)

	backend := testBackend{
		t:            t,
		relay:        relay,
		beaconClient: bc,
		datastore:    ds,
		redis:        redisCache,
	}
	return &backend
}

func (be *testBackend) request(method string, path string, payload any) *httptest.ResponseRecorder {
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
	rr := httptest.NewRecorder()
	be.relay.getRouter().ServeHTTP(rr, req)
	return rr
}

// func createKey() {
// 	sk, pk, err := bls.GenerateNewKeypair()
// 	if err != nil {
// 		return nil, err
// 	}

// 	var pubKey types.PublicKey
// 	pubKey.FromSlice(pk.Compress())
// }

func generateSignedValidatorRegistration(sk *bls.SecretKey, feeRecipient types.Address, timestamp uint64) (*types.SignedValidatorRegistration, error) {
	var err error
	if sk == nil {
		sk, _, err = bls.GenerateNewKeypair()
		if err != nil {
			return nil, err
		}
	}

	blsPubKey := bls.PublicKeyFromSecretKey(sk)

	var pubKey types.PublicKey
	pubKey.FromSlice(blsPubKey.Compress())
	msg := &types.RegisterValidatorRequestMessage{
		FeeRecipient: feeRecipient,
		Timestamp:    timestamp,
		Pubkey:       pubKey,
	}

	sig, err := types.SignMessage(msg, builderSigningDomain, sk)
	if err != nil {
		return nil, err
	}

	return &types.SignedValidatorRegistration{
		Message:   msg,
		Signature: sig,
	}, nil
}

func TestWebserver(t *testing.T) {
	t.Run("errors when webserver is already existing", func(t *testing.T) {
		backend := newTestBackend(t)
		backend.relay.srvStarted.Store(true)
		err := backend.relay.StartServer()
		require.Error(t, err)
	})

	// t.Run("webserver error on invalid listenAddr", func(t *testing.T) {
	// 	backend := newTestBackend(t)
	// 	backend.relay.opts.ListenAddr = "localhost:876543"
	// 	err := backend.relay.StartServer()
	// 	require.Error(t, err)
	// })

	// t.Run("webserver starts and closes normally", func(t *testing.T) {
	// 	backend := newTestBackend(t)
	// 	connectionClosed := make(chan struct{})
	// 	go func() {
	// 		err := backend.relay.StartServer()
	// 		require.NoError(t, err)
	// 		time.Sleep(time.Millisecond * 100)
	// 		err = backend.relay.Stop()
	// 		require.NoError(t, err)
	// 		close(connectionClosed)
	// 	}()
	// 	<-connectionClosed
	// })
}

func TestWebserverRootHandler(t *testing.T) {
	backend := newTestBackend(t)
	rr := backend.request(http.MethodGet, "/", nil)
	require.Equal(t, http.StatusNotFound, rr.Code)
	// require.Equal(t, "text/html; charset=utf-8", rr.Header().Get("Content-Type"))
}

func TestStatus(t *testing.T) {
	backend := newTestBackend(t)
	path := "/eth/v1/builder/status"
	rr := backend.request(http.MethodGet, path, common.ValidPayloadRegisterValidator)
	require.Equal(t, http.StatusOK, rr.Code)
}

func TestRegisterValidator(t *testing.T) {
	path := "/eth/v1/builder/validators"

	t.Run("Normal function", func(t *testing.T) {
		t.Skip() // has an error at verifying the sig

		backend := newTestBackend(t)
		backend.relay.startValidatorRegistrationWorkers()
		pubkeyHex := common.ValidPayloadRegisterValidator.Message.Pubkey.PubkeyHex()
		index := uint64(17)
		backend.redis.SetKnownValidator(pubkeyHex, index)

		// Update datastore
		backend.datastore.RefreshKnownValidators()
		require.True(t, backend.datastore.IsKnownValidator(pubkeyHex))
		pkH, ok := backend.datastore.GetKnownValidatorPubkeyByIndex(index)
		require.True(t, ok)
		require.Equal(t, pubkeyHex, pkH)

		rr := backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{common.ValidPayloadRegisterValidator})
		require.Equal(t, http.StatusOK, rr.Code)
		time.Sleep(20 * time.Millisecond) // registrations are processed asynchronously

		req, err := backend.datastore.GetValidatorRegistration(pubkeyHex)
		require.NoError(t, err)
		require.NotNil(t, req)
		require.Equal(t, pubkeyHex, req.Message.Pubkey.PubkeyHex())
	})

	t.Run("not a known validator", func(t *testing.T) {
		backend := newTestBackend(t)

		rr := backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{common.ValidPayloadRegisterValidator})
		require.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("Reject registration for >10sec into the future", func(t *testing.T) {
		backend := newTestBackend(t)

		// Allow +10 sec
		td := uint64(time.Now().Unix())
		payload, err := generateSignedValidatorRegistration(nil, types.Address{1}, td+10)
		require.NoError(t, err)
		backend.redis.SetKnownValidator(payload.Message.Pubkey.PubkeyHex(), 1)
		backend.datastore.RefreshKnownValidators()

		rr := backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{*payload})
		require.Equal(t, http.StatusOK, rr.Code)

		// Disallow +11 sec
		td = uint64(time.Now().Unix())
		payload, err = generateSignedValidatorRegistration(nil, types.Address{1}, td+12)
		require.NoError(t, err)
		backend.redis.SetKnownValidator(payload.Message.Pubkey.PubkeyHex(), 1)
		backend.datastore.RefreshKnownValidators()

		rr = backend.request(http.MethodPost, path, []types.SignedValidatorRegistration{*payload})
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "timestamp too far in the future")
	})
}

func TestBuilderApiGetValidators(t *testing.T) {
	path := "/relay/v1/builder/validators"

	backend := newTestBackend(t)
	backend.relay.proposerDutiesResponse = []types.BuilderGetValidatorsResponseEntry{
		types.BuilderGetValidatorsResponseEntry{
			Slot:  1,
			Entry: &common.ValidPayloadRegisterValidator},
	}

	rr := backend.request(http.MethodGet, path, nil)
	require.Equal(t, http.StatusOK, rr.Code)

	resp := []types.BuilderGetValidatorsResponseEntry{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, 1, len(resp))
	require.Equal(t, uint64(1), resp[0].Slot)
	require.Equal(t, common.ValidPayloadRegisterValidator, *resp[0].Entry)
}

// func TestGetHeader(t *testing.T) {
// 	getPath := func(slot uint64, parentHash types.Hash, pubkey types.PublicKey) string {
// 		return fmt.Sprintf("/eth/v1/builder/header/%d/%s/%s", slot, parentHash.String(), pubkey.String())
// 	}

// 	hash := _HexToHash("0xe28385e7bd68df656cd0042b74b69c3104b5356ed1f20eb69f1f925df47a3ab7")
// 	pubkey := _HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
// 	path := getPath(1, hash, pubkey)
// 	require.Equal(t, "/eth/v1/builder/header/1/0xe28385e7bd68df656cd0042b74b69c3104b5356ed1f20eb69f1f925df47a3ab7/0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2", path)

// 	t.Run("Okay response from relay", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, time.Second)
// 		rr := backend.request(t, http.MethodGet, path, nil)
// 		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 	})

// 	t.Run("Bad response from relays", func(t *testing.T) {
// 		backend := newTestBackend(t, 2, time.Second)
// 		resp := makeGetHeaderResponse(12345)
// 		resp.Data.Message.Header.BlockHash = types.NilHash

// 		// 1/2 failing responses are okay
// 		backend.relays[0].GetHeaderResponse = resp
// 		rr := backend.request(t, http.MethodGet, path, nil)
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 1, backend.relays[1].getRequestCount(path))
// 		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

// 		// 2/2 failing responses are okay
// 		backend.relays[1].GetHeaderResponse = resp
// 		rr = backend.request(t, http.MethodGet, path, nil)
// 		require.Equal(t, 2, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 2, backend.relays[1].getRequestCount(path))
// 		require.Equal(t, http.StatusBadGateway, rr.Code, rr.Body.String())
// 	})

// 	t.Run("Use header with highest value", func(t *testing.T) {
// 		backend := newTestBackend(t, 3, time.Second)
// 		backend.relays[0].GetHeaderResponse = makeGetHeaderResponse(12345)
// 		backend.relays[1].GetHeaderResponse = makeGetHeaderResponse(12347)
// 		backend.relays[2].GetHeaderResponse = makeGetHeaderResponse(12346)

// 		rr := backend.request(t, http.MethodGet, path, nil)
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 1, backend.relays[1].getRequestCount(path))
// 		require.Equal(t, 1, backend.relays[2].getRequestCount(path))
// 		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
// 		resp := new(types.GetHeaderResponse)
// 		err := json.Unmarshal(rr.Body.Bytes(), resp)
// 		require.NoError(t, err)
// 		require.Equal(t, types.IntToU256(12347), resp.Data.Message.Value)
// 	})
// }

// func TestGetPayload(t *testing.T) {
// 	path := "/eth/v1/builder/blinded_blocks"

// 	payload := types.SignedBlindedBeaconBlock{
// 		Signature: _HexToSignature("0x8682789b16da95ba437a5b51c14ba4e112b50ceacd9730f697c4839b91405280e603fc4367283aa0866af81a21c536c4c452ace2f4146267c5cf6e959955964f4c35f0cedaf80ed99ffc32fe2d28f9390bb30269044fcf20e2dd734c7b287d14"),
// 		Message: &types.BlindedBeaconBlock{
// 			Slot:          1,
// 			ProposerIndex: 1,
// 			ParentRoot:    types.Root{0x01},
// 			StateRoot:     types.Root{0x02},
// 			Body: &types.BlindedBeaconBlockBody{
// 				RandaoReveal: types.Signature{0xa1},
// 				Graffiti:     types.Hash{0xa2},
// 				ExecutionPayloadHeader: &types.ExecutionPayloadHeader{
// 					ParentHash:   _HexToHash("0xe28385e7bd68df656cd0042b74b69c3104b5356ed1f20eb69f1f925df47a3ab7"),
// 					BlockHash:    _HexToHash("0xe28385e7bd68df656cd0042b74b69c3104b5356ed1f20eb69f1f925df47a3ab1"),
// 					BlockNumber:  12345,
// 					FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
// 				},
// 			},
// 		},
// 	}

// 	t.Run("Okay response from relay", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, time.Second)
// 		rr := backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))

// 		resp := new(types.GetPayloadResponse)
// 		err := json.Unmarshal(rr.Body.Bytes(), resp)
// 		require.NoError(t, err)
// 		require.Equal(t, payload.Message.Body.ExecutionPayloadHeader.BlockHash, resp.Data.BlockHash)
// 	})

// 	t.Run("Bad response from relays", func(t *testing.T) {
// 		backend := newTestBackend(t, 2, time.Second)
// 		resp := new(types.GetPayloadResponse)

// 		// Delays are needed because otherwise one relay might never receive a request
// 		backend.relays[0].ResponseDelay = 10 * time.Millisecond
// 		backend.relays[1].ResponseDelay = 10 * time.Millisecond

// 		// 1/2 failing responses are okay
// 		backend.relays[0].GetPayloadResponse = resp
// 		rr := backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 1, backend.relays[1].getRequestCount(path))
// 		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

// 		// 2/2 failing responses are okay
// 		backend.relays[1].GetPayloadResponse = resp
// 		rr = backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, 2, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 2, backend.relays[1].getRequestCount(path))
// 		require.Equal(t, http.StatusBadGateway, rr.Code, rr.Body.String())
// 	})
// }
