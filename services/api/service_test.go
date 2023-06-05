package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	builderCapella "github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
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

	ds, err := datastore.NewDatastore(common.TestLog, redisCache, nil, db)
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

func (be *testBackend) requestBytes(method, path string, payload []byte, headers map[string]string) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	req, err = http.NewRequest(method, path, bytes.NewReader(payload))
	require.NoError(be.t, err)

	// Set headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// lfg
	rr := httptest.NewRecorder()
	be.relay.getRouter().ServeHTTP(rr, req)
	return rr
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

func TestBuilderSubmitBlockSSZ(t *testing.T) {
	requestPayloadJSONBytes, err := os.ReadFile("../../testdata/submitBlockPayloadCapella_Goerli.json")
	require.NoError(t, err)

	req := new(common.BuilderSubmitBlockRequest)
	err = json.Unmarshal(requestPayloadJSONBytes, &req)
	require.NoError(t, err)

	reqSSZ, err := req.Capella.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, 352239, len(reqSSZ))

	test := new(builderCapella.SubmitBlockRequest)
	err = test.UnmarshalSSZ(reqSSZ)
	require.NoError(t, err)
}

func TestBuilderSubmitBlock(t *testing.T) {
	path := "/relay/v1/builder/blocks"
	backend := newTestBackend(t, 1)

	headSlot := uint64(32)
	submissionSlot := headSlot + 1
	submissionTimestamp := 1606824419

	// Payload attributes
	payloadJSONFilename := "../../testdata/submitBlockPayloadCapella_Goerli.json"
	parentHash := "0xbd3291854dc822b7ec585925cda0e18f06af28fa2886e15f52d52dd4b6f94ed6"
	feeRec, err := types.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35")
	require.NoError(t, err)
	withdrawalsRoot, err := hexutil.Decode("0xb15ed76298ff84a586b1d875df08b6676c98dfe9c7cd73fab88450348d8e70c8")
	require.NoError(t, err)
	prevRandao := "0x9962816e9d0a39fd4c80935338a741dc916d1545694e41eb5a505e1a3098f9e4"

	// Setup the test relay backend
	backend.relay.headSlot.Store(headSlot)
	backend.relay.capellaEpoch = 1
	backend.relay.proposerDutiesMap = make(map[uint64]*common.BuilderGetValidatorsResponseEntry)
	backend.relay.proposerDutiesMap[headSlot+1] = &common.BuilderGetValidatorsResponseEntry{
		Slot: headSlot,
		Entry: &types.SignedValidatorRegistration{
			Message: &types.RegisterValidatorRequestMessage{
				FeeRecipient: feeRec,
			},
		},
	}
	backend.relay.payloadAttributes = make(map[string]payloadAttributesHelper)
	backend.relay.payloadAttributes[parentHash] = payloadAttributesHelper{
		slot:       submissionSlot,
		parentHash: parentHash,
		payloadAttributes: beaconclient.PayloadAttributes{
			PrevRandao: prevRandao,
		},
		withdrawalsRoot: phase0.Root(withdrawalsRoot),
	}

	// Prepare the request payload
	req := new(common.BuilderSubmitBlockRequest)
	requestPayloadJSONBytes, err := os.ReadFile(payloadJSONFilename)
	require.NoError(t, err)
	err = json.Unmarshal(requestPayloadJSONBytes, &req)
	require.NoError(t, err)

	// Update
	req.Capella.Message.Slot = submissionSlot
	req.Capella.ExecutionPayload.Timestamp = uint64(submissionTimestamp)

	// Send JSON encoded request
	reqJSONBytes, err := req.Capella.MarshalJSON()
	require.NoError(t, err)
	require.Equal(t, 704810, len(reqJSONBytes))
	reqJSONBytes2, err := json.Marshal(req.Capella)
	require.NoError(t, err)
	require.Equal(t, reqJSONBytes, reqJSONBytes2)
	rr := backend.requestBytes(http.MethodPost, path, reqJSONBytes, nil)
	require.Contains(t, rr.Body.String(), "invalid signature")
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Send SSZ encoded request
	reqSSZBytes, err := req.Capella.MarshalSSZ()
	require.NoError(t, err)
	require.Equal(t, 352239, len(reqSSZBytes))
	rr = backend.requestBytes(http.MethodPost, path, reqSSZBytes, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	require.Contains(t, rr.Body.String(), "invalid signature")
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Send JSON+GZIP encoded request
	headers := map[string]string{
		"Content-Encoding": "gzip",
	}
	jsonGzip := gzipBytes(t, reqJSONBytes)
	require.Equal(t, 207788, len(jsonGzip))
	rr = backend.requestBytes(http.MethodPost, path, jsonGzip, headers)
	require.Contains(t, rr.Body.String(), "invalid signature")
	require.Equal(t, http.StatusBadRequest, rr.Code)

	// Send SSZ+GZIP encoded request
	headers = map[string]string{
		"Content-Type":     "application/octet-stream",
		"Content-Encoding": "gzip",
	}

	sszGzip := gzipBytes(t, reqSSZBytes)
	require.Equal(t, 195923, len(sszGzip))
	rr = backend.requestBytes(http.MethodPost, path, sszGzip, headers)
	require.Contains(t, rr.Body.String(), "invalid signature")
	require.Equal(t, http.StatusBadRequest, rr.Code)
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(b)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}
