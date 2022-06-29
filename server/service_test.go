package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var genesisForkVersionHex = "0x00000000"

type testBackend struct {
	relay *RelayService
}

func newTestBackend(t require.TestingT, numRelays int, relayTimeout time.Duration) *testBackend {
	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)

	redisService, err := NewRedisService(redisTestServer.Addr())
	require.NoError(t, err)
	common.TestLog.Logger.SetLevel(logrus.FatalLevel)
	service, err := NewRelayService("localhost:12345", nil, common.TestLog, genesisForkVersionHex, redisService)
	require.NoError(t, err)

	backend := testBackend{relay: service}
	return &backend
}

func (be *testBackend) request(t require.TestingT, method string, path string, payload any) *httptest.ResponseRecorder {
	var req *http.Request
	var err error

	if payload == nil {
		req, err = http.NewRequest(method, path, bytes.NewReader(nil))
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		require.NoError(t, err2)
		req, err = http.NewRequest(method, path, bytes.NewReader(payloadBytes))
	}

	require.NoError(t, err)
	rr := httptest.NewRecorder()
	be.relay.getRouter().ServeHTTP(rr, req)
	return rr
}

func generateSignature(feeRecipient types.Address, timestamp uint64, domain types.Domain) (*types.SignedValidatorRegistration, error) {
	sk, pk, err := bls.GenerateNewKeypair()
	if err != nil {
		return nil, err
	}

	var pubKey types.PublicKey
	pubKey.FromSlice(pk.Compress())
	msg := &types.RegisterValidatorRequestMessage{
		FeeRecipient: feeRecipient,
		Timestamp:    timestamp,
		Pubkey:       pubKey,
	}

	sig, err := types.SignMessage(msg, domain, sk)
	if err != nil {
		return nil, err
	}

	return &types.SignedValidatorRegistration{
		Message:   msg,
		Signature: sig,
	}, nil
}

func BenchmarkHandleRegistration(b *testing.B) {
	backend := newTestBackend(b, 1, time.Second)
	path := "/eth/v1/builder/validators"
	benchmarks := []struct {
		name        string
		payloadSize int
	}{
		{"payload of size 10", 10},
		{"payload of size 100", 100},
		{"payload of size 1000", 1000},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			payload := []types.SignedValidatorRegistration{}
			for i := 0; i < bm.payloadSize; i++ {
				feeRecipient := common.ValidPayloadRegisterValidator.Message.FeeRecipient
				reg, err := generateSignature(feeRecipient, uint64(i), backend.relay.builderSigningDomain)
				if err != nil {
					b.Fatal(err)
				}
				payload = append(payload, *reg)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				backend.request(b, http.MethodPost, path, payload)
			}
		})
	}
}

// func TestWebserver(t *testing.T) {
// 	t.Run("errors when webserver is already existing", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, time.Second)
// 		backend.boost.srv = &http.Server{}
// 		err := backend.boost.StartHTTPServer()
// 		require.Error(t, err)
// 	})

// 	t.Run("webserver error on invalid listenAddr", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, time.Second)
// 		backend.boost.listenAddr = "localhost:876543"
// 		err := backend.boost.StartHTTPServer()
// 		require.Error(t, err)
// 	})

// 	// t.Run("webserver starts normally", func(t *testing.T) {
// 	// 	backend := newTestBackend(t, 1, time.Second)
// 	// 	go func() {
// 	// 		err := backend.boost.StartHTTPServer()
// 	// 		require.NoError(t, err)
// 	// 	}()
// 	// 	time.Sleep(time.Millisecond * 100)
// 	// 	backend.boost.srv.Close()
// 	// })
// }

// func TestWebserverRootHandler(t *testing.T) {
// 	rr := testRelayRequest(t, "GET", "/", nil)
// 	require.Equal(t, http.StatusOK, rr.Code)
// 	require.Equal(t, "{}", rr.Body.String())
// }

// // Example good registerValidator payload
// var payloadRegisterValidator = types.SignedValidatorRegistration{
// 	Message: &types.RegisterValidatorRequestMessage{
// 		FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
// 		Timestamp:    1234356,
// 		GasLimit:     278234191203,
// 		Pubkey:       _HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2"),
// 	},
// 	Signature: _HexToSignature("0x8682789b16da95ba437a5b51c14ba4e112b50ceacd9730f697c4839b91405280e603fc4367283aa0866af81a21c536c4c452ace2f4146267c5cf6e959955964f4c35f0cedaf80ed99ffc32fe2d28f9390bb30269044fcf20e2dd734c7b287d14"),
// }

// func TestStatus(t *testing.T) {
// 	backend := newTestBackend(t, 1, time.Second)
// 	path := "/eth/v1/builder/status"
// 	rr := backend.request(t, http.MethodGet, path, payloadRegisterValidator)
// 	require.Equal(t, http.StatusOK, rr.Code)
// 	require.Equal(t, 0, backend.relays[0].getRequestCount(path))
// }

// func TestRegisterValidator(t *testing.T) {
// 	path := "/eth/v1/builder/validators"
// 	payload := types.SignedValidatorRegistration{
// 		Message: &types.RegisterValidatorRequestMessage{
// 			FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
// 			Timestamp:    1234356,
// 			Pubkey:       _HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2"),
// 		},
// 		Signature: _HexToSignature("0x8682789b16da95ba437a5b51c14ba4e112b50ceacd9730f697c4839b91405280e603fc4367283aa0866af81a21c536c4c452ace2f4146267c5cf6e959955964f4c35f0cedaf80ed99ffc32fe2d28f9390bb30269044fcf20e2dd734c7b287d14"),
// 	}

// 	t.Run("Normal function", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, time.Second)
// 		rr := backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusOK, rr.Code)
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 	})

// 	t.Run("Relay error response", func(t *testing.T) {
// 		backend := newTestBackend(t, 2, time.Second)

// 		rr := backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusOK, rr.Code)
// 		require.Equal(t, 1, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 1, backend.relays[1].getRequestCount(path))

// 		// Now make one relay return an error
// 		backend.relays[0].HandlerOverride = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }
// 		rr = backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusOK, rr.Code)
// 		require.Equal(t, 2, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 2, backend.relays[1].getRequestCount(path))

// 		// Now make both relays return an error - which should cause the request to fail
// 		backend.relays[1].HandlerOverride = func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }
// 		rr = backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusBadGateway, rr.Code)
// 		require.Equal(t, 3, backend.relays[0].getRequestCount(path))
// 		require.Equal(t, 3, backend.relays[1].getRequestCount(path))
// 	})

// 	t.Run("mev-boost relay timeout works with slow relay", func(t *testing.T) {
// 		backend := newTestBackend(t, 1, 5*time.Millisecond) // 10ms max
// 		rr := backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusOK, rr.Code)

// 		// Now make the relay return slowly, mev-boost should return an error
// 		backend.relays[0].ResponseDelay = 10 * time.Millisecond
// 		rr = backend.request(t, http.MethodPost, path, payload)
// 		require.Equal(t, http.StatusBadGateway, rr.Code)
// 		require.Equal(t, 2, backend.relays[0].getRequestCount(path))
// 	})
// }

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
