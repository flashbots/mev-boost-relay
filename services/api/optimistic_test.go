package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

const (
	slot        = uint64(41)
	collateral  = 1000
	builderID   = "builder0x69"
	randao      = "01234567890123456789012345678901"
	emptyHash   = "0x0000000000000000000000000000000000000000000000000000000000000000"
	proposerInd = uint64(987)
	genesis     = 1606824023
)

var (
	feeRecipient = bellatrix.ExecutionAddress{0x02}
	errFake      = fmt.Errorf("foo error")
)

func getTestBidTrace(pubkey phase0.BLSPubKey, value uint64) *common.BidTraceV2 {
	return &common.BidTraceV2{
		BidTrace: v1.BidTrace{
			Slot:                 slot,
			BuilderPubkey:        pubkey,
			ProposerFeeRecipient: feeRecipient,
			Value:                uint256.NewInt(value),
		},
	}
}

type blockRequestOpts struct {
	pubkey     phase0.BLSPubKey
	secretkey  *bls.SecretKey
	blockValue uint64
	domain     boostTypes.Domain
}

func generateKeyPair(t *testing.T) (*phase0.BLSPubKey, *bls.SecretKey) {
	t.Helper()
	// Setup test key pair.
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	blsPubkey, err := bls.PublicKeyFromSecretKey(sk)
	require.NoError(t, err)
	pkBytes := blsPubkey.Bytes()
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], pkBytes[:])
	return &pubkey, sk
}

func startTestBackend(t *testing.T, pubkey *phase0.BLSPubKey) *testBackend {
	t.Helper()
	pkStr := pubkey.String()

	// Setup test backend.
	backend := newTestBackend(t, 1)
	backend.relay.genesisInfo = &beaconclient.GetGenesisResponse{}
	backend.relay.genesisInfo.Data.GenesisTime = 0
	backend.relay.proposerDutiesMap = map[uint64]*common.BuilderGetValidatorsResponseEntry{
		slot: {
			Entry: &boostTypes.SignedValidatorRegistration{
				Message: &boostTypes.RegisterValidatorRequestMessage{
					FeeRecipient: [20]byte(feeRecipient),
					GasLimit:     5000,
					Timestamp:    0xffffffff,
					Pubkey:       [48]byte(phase0.BLSPubKey{}),
				},
			},
		},
	}
	backend.relay.opts.BlockBuilderAPI = true
	backend.relay.beaconClient = beaconclient.NewMockMultiBeaconClient()
	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{}
	backend.relay.blockBuildersCache = map[string]*blockBuilderCacheEntry{
		pkStr: {
			status: common.BuilderStatus{
				IsHighPrio:   true,
				IsOptimistic: true,
			},
			collateral: big.NewInt(int64(collateral)),
		},
	}

	// Setup test db, redis, and datastore.
	mockDB := &database.MockDB{
		Builders: map[string]*database.BlockBuilderEntry{
			pkStr: {
				BuilderPubkey: pkStr,
				IsHighPrio:    true,
				IsOptimistic:  true,
				BuilderID:     builderID,
				Collateral:    strconv.Itoa(collateral),
			},
		},
		Demotions: map[string]bool{},
		Refunds:   map[string]bool{},
	}
	redisTestServer, err := miniredis.Run()
	require.NoError(t, err)
	mockRedis, err := datastore.NewRedisCache("", redisTestServer.Addr(), "")
	require.NoError(t, err)
	mockDS, err := datastore.NewDatastore(mockRedis, nil, mockDB)
	require.NoError(t, err)

	backend.relay.datastore = mockDS
	backend.relay.redis = mockRedis
	backend.relay.db = mockDB

	// Prepare redis
	// err = backend.relay.redis.SetKnownValidator(boostTypes.NewPubkeyHex(pubkey.String()), proposerInd)
	// require.NoError(t, err)

	// count, err := backend.relay.datastore.RefreshKnownValidators()
	// require.NoError(t, err)
	// require.Equal(t, count, 1)

	backend.relay.headSlot.Store(40)
	return backend
}

func runOptimisticBlockSubmission(t *testing.T, opts blockRequestOpts, simErr error, backend *testBackend) *httptest.ResponseRecorder {
	t.Helper()
	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
		simulationError: simErr,
	}

	req := common.TestBuilderSubmitBlockRequest(opts.secretkey, getTestBidTrace(opts.pubkey, opts.blockValue))
	rr := backend.request(http.MethodPost, pathSubmitNewBlock, &req)

	// Let updates happen async.
	time.Sleep(100 * time.Millisecond)
	return rr
}

func TestSimulateBlock(t *testing.T) {
	cases := []struct {
		description     string
		simulationError error
		expectError     bool
	}{
		{
			description: "success",
		},
		{
			description:     "simulation_error",
			simulationError: errFake,
			expectError:     true,
		},
		{
			description:     "block_already_known",
			simulationError: fmt.Errorf(ErrBlockAlreadyKnown), //nolint:goerr113
		},
		{
			description:     "missing_trie_node",
			simulationError: fmt.Errorf(ErrMissingTrieNode + "23e21f94cd97b3b27ae5c758277639dd387a6e3da5923c5485f24ec6c71e16b8 (path ) <nil>"), //nolint:goerr113
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			pubkey, secretkey := generateKeyPair(t)
			backend := startTestBackend(t, pubkey)
			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
				simulationError: tc.simulationError,
			}
			_, simErr := backend.relay.simulateBlock(context.Background(), blockSimOptions{
				isHighPrio: true,
				log:        backend.relay.log,
				builder: &blockBuilderCacheEntry{
					status: common.BuilderStatus{
						IsOptimistic: true,
					},
				},
				req: &common.BuilderBlockValidationRequest{
					BuilderSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
						secretkey, getTestBidTrace(*pubkey, collateral)),
				},
			})
			if tc.expectError {
				require.Equal(t, tc.simulationError, simErr)
			}
		})
	}
}

func TestProcessOptimisticBlock(t *testing.T) {
	cases := []struct {
		description     string
		wantStatus      common.BuilderStatus
		simulationError error
	}{
		{
			description: "success",
			wantStatus: common.BuilderStatus{
				IsOptimistic: true,
				IsHighPrio:   true,
			},
		},
		{
			description: "simulation_error",
			wantStatus: common.BuilderStatus{
				IsOptimistic: false,
				IsHighPrio:   true,
			},
			simulationError: errFake,
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			pubkey, secretkey := generateKeyPair(t)
			backend := startTestBackend(t, pubkey)
			pkStr := pubkey.String()
			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
				simulationError: tc.simulationError,
			}
			simResultC := make(chan *blockSimResult, 1)
			backend.relay.processOptimisticBlock(blockSimOptions{
				isHighPrio: true,
				log:        backend.relay.log,
				builder: &blockBuilderCacheEntry{
					status: common.BuilderStatus{
						IsOptimistic: true,
					},
				},
				req: &common.BuilderBlockValidationRequest{
					BuilderSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
						secretkey, getTestBidTrace(*pubkey, collateral)),
				},
			}, simResultC)

			// Check status in db.
			builder, err := backend.relay.db.GetBlockBuilderByPubkey(pkStr)
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus.IsOptimistic, builder.IsOptimistic)
			require.Equal(t, tc.wantStatus.IsHighPrio, builder.IsHighPrio)

			// Make sure channel receives correct result
			simResult := <-simResultC
			require.True(t, simResult.optimisticSubmission)
			require.Equal(t, tc.simulationError, simResult.validationErr)
			require.Nil(t, simResult.requestErr)
			require.True(t, simResult.wasSimulated)

			// Check demotion but no refund.
			if tc.simulationError != nil {
				mockDB, ok := backend.relay.db.(*database.MockDB)
				require.True(t, ok)
				require.True(t, mockDB.Demotions[pkStr])
				require.False(t, mockDB.Refunds[pkStr])
			}
		})
	}
}

func TestDemoteBuilder(t *testing.T) {
	wantStatus := common.BuilderStatus{
		IsOptimistic: false,
		IsHighPrio:   true,
	}
	pubkey, secretkey := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	pkStr := pubkey.String()
	req := common.TestBuilderSubmitBlockRequest(secretkey, getTestBidTrace(*pubkey, collateral))
	backend.relay.demoteBuilder(pkStr, &req, errFake)

	// Check status in db.
	builder, err := backend.relay.db.GetBlockBuilderByPubkey(pkStr)
	require.NoError(t, err)
	require.Equal(t, wantStatus.IsOptimistic, builder.IsOptimistic)
	require.Equal(t, wantStatus.IsHighPrio, builder.IsHighPrio)

	// Check demotion and refund statuses.
	mockDB, ok := backend.relay.db.(*database.MockDB)
	require.True(t, ok)
	require.True(t, mockDB.Demotions[pkStr])
}

func TestPrepareBuildersForSlot(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	pkStr := pubkey.String()
	// Clear cache.
	backend.relay.blockBuildersCache = map[string]*blockBuilderCacheEntry{}
	backend.relay.prepareBuildersForSlot(slot + 1)
	entry, ok := backend.relay.blockBuildersCache[pkStr]
	require.True(t, ok)
	require.Equal(t, true, entry.status.IsHighPrio)
	require.Equal(t, true, entry.status.IsOptimistic)
	require.Equal(t, false, entry.status.IsBlacklisted)
	require.Zero(t, entry.collateral.Cmp(big.NewInt(int64(collateral))))
}

func TestBuilderApiSubmitNewBlockOptimistic(t *testing.T) {
	testCases := []struct {
		description     string
		wantStatus      common.BuilderStatus
		simulationError error
		expectDemotion  bool
		httpCode        uint64
		blockValue      uint64
	}{
		{
			description: "success_value_less_than_collateral",
			wantStatus: common.BuilderStatus{
				IsOptimistic: true,
				IsHighPrio:   true,
			},
			simulationError: nil,
			expectDemotion:  false,
			httpCode:        200, // success
			blockValue:      collateral - 1,
		},
		{
			description: "success_value_greater_than_collateral",
			wantStatus: common.BuilderStatus{
				IsOptimistic: true,
				IsHighPrio:   true,
			},
			simulationError: nil,
			expectDemotion:  false,
			httpCode:        200, // success
			blockValue:      collateral + 1,
		},
		{
			description: "failure_value_more_than_collateral",
			wantStatus: common.BuilderStatus{
				IsOptimistic: true,
				IsHighPrio:   true,
			},
			simulationError: errFake,
			expectDemotion:  false,
			httpCode:        400, // failure (in pessimistic mode, block sim failure happens in response path)
			blockValue:      collateral + 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			pubkey, secretkey := generateKeyPair(t)
			backend := startTestBackend(t, pubkey)
			backend.relay.optimisticSlot.Store(slot)
			backend.relay.capellaEpoch = 1
			var randaoHash boostTypes.Hash
			err := randaoHash.FromSlice([]byte(randao))
			require.NoError(t, err)
			withRoot, err := ComputeWithdrawalsRoot([]*consensuscapella.Withdrawal{})
			require.NoError(t, err)
			backend.relay.payloadAttributes[emptyHash] = payloadAttributesHelper{
				slot:            slot,
				withdrawalsRoot: withRoot,
				payloadAttributes: beaconclient.PayloadAttributes{
					PrevRandao: randaoHash.String(),
				},
			}
			pkStr := pubkey.String()
			rr := runOptimisticBlockSubmission(t, blockRequestOpts{
				secretkey:  secretkey,
				pubkey:     *pubkey,
				blockValue: tc.blockValue,
				domain:     backend.relay.opts.EthNetDetails.DomainBuilder,
			}, tc.simulationError, backend)

			// Check http code.
			require.Equal(t, uint64(rr.Code), tc.httpCode)

			// Check status in db.
			builder, err := backend.relay.db.GetBlockBuilderByPubkey(pkStr)
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus.IsOptimistic, builder.IsOptimistic)
			require.Equal(t, tc.wantStatus.IsHighPrio, builder.IsHighPrio)

			// Check demotion status is set to expected and refund is false.
			mockDB, ok := backend.relay.db.(*database.MockDB)
			require.True(t, ok)
			require.Equal(t, mockDB.Demotions[pkStr], tc.expectDemotion)
			require.False(t, mockDB.Refunds[pkStr])
		})
	}
}

func TestInternalBuilderStatus(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	// Set all to false initially.
	err := backend.relay.db.SetBlockBuilderStatus(pubkey.String(), common.BuilderStatus{})
	require.NoError(t, err)
	path := "/internal/v1/builder/" + pubkey.String()

	setAndGetStatus := func(arg string, expected common.BuilderStatus) {
		// Set & Get.
		rr := backend.request(http.MethodPost, path+arg, nil)
		require.Equal(t, rr.Code, http.StatusOK)

		rr = backend.request(http.MethodGet, path, nil)
		require.Equal(t, rr.Code, http.StatusOK)
		resp := &database.BlockBuilderEntry{}
		err := json.Unmarshal(rr.Body.Bytes(), &resp)
		require.NoError(t, err)
		require.Equal(t, expected.IsHighPrio, resp.IsHighPrio)
		require.Equal(t, expected.IsBlacklisted, resp.IsBlacklisted)
		require.Equal(t, expected.IsOptimistic, resp.IsOptimistic)
	}
	// Add each on.
	setAndGetStatus("?high_prio=true", common.BuilderStatus{IsHighPrio: true})
	setAndGetStatus("?blacklisted=true", common.BuilderStatus{IsHighPrio: true, IsBlacklisted: true})
	setAndGetStatus("?optimistic=true", common.BuilderStatus{IsHighPrio: true, IsBlacklisted: true, IsOptimistic: true})
}

func TestInternalBuilderCollateral(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	path := "/internal/v1/builder/collateral/" + pubkey.String()

	// Set & Get.
	rr := backend.request(http.MethodPost, path+"?collateral=builder0x69&value=10000", nil)
	require.Equal(t, rr.Code, http.StatusOK)

	rr = backend.request(http.MethodGet, "/internal/v1/builder/"+pubkey.String(), nil)
	require.Equal(t, rr.Code, http.StatusOK)
	resp := &database.BlockBuilderEntry{}
	err := json.Unmarshal(rr.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Equal(t, resp.BuilderID, "builder0x69")
	require.Equal(t, resp.Collateral, "10000")
}

func TestBuilderApiSubmitNewBlockOptimisticV2_fail_cancellations(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	outBytes := make([]byte, 10)

	// Disable cancellations.
	backend.relay.ffEnableCancellations = false

	// Set request with cancellations true.
	rr := backend.requestBytes(http.MethodPost, pathSubmitNewBlockV2+"?cancellations=1", outBytes, map[string]string{})

	// Check bad request is returned.
	require.Equal(t, rr.Code, 400)
}

func TestBuilderApiSubmitNewBlockOptimisticV2_fail_gzip(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	outBytes := make([]byte, 10)

	// Set request with gzip.
	rr := backend.requestBytes(http.MethodPost, pathSubmitNewBlockV2, outBytes, map[string]string{"Content-Encoding": "gzip"})

	// Check bad request is returned.
	require.Equal(t, rr.Code, 400)
}

func TestBuilderApiSubmitNewBlockOptimisticV2_fail_read_header(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	outBytes := make([]byte, 0) // 0 bytes.

	// Valid request but no bytes.
	rr := backend.requestBytes(http.MethodPost, pathSubmitNewBlockV2, outBytes, map[string]string{})

	// Check bad request is returned.
	require.Equal(t, rr.Code, 400)
}

func TestBuilderApiSubmitNewBlockOptimisticV2_fail_ssz_decode_header(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	outBytes := make([]byte, 944) // 944 bytes is min required to try ssz decoding.
	outBytes[0] = 0xaa

	// Valid request but no bytes.
	rr := backend.requestBytes(http.MethodPost, pathSubmitNewBlockV2, outBytes, map[string]string{})

	// Check bad request is returned.
	require.Equal(t, rr.Code, 400)
}

func TestBuilderApiSubmitNewBlockOptimisticV2_full(t *testing.T) {
	pubkey, secretkey := generateKeyPair(t)

	// Construct our test requests.
	cleanReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	badSigReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	badSigReq.Signature[0] = 0xaa
	invalidSigReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	invalidSigReq.Message.Slot += 1
	badTimestampReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	badTimestampReq.ExecutionPayloadHeader.Timestamp -= 1
	badWithdrawalsRootReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	badWithdrawalsRootReq.ExecutionPayloadHeader.WithdrawalsRoot[0] = 0xaa

	// Bad requests that need signatures.
	bidBadFeeRecipient := getTestBidTrace(*pubkey, 10)
	bidBadFeeRecipient.ProposerFeeRecipient[0] = 0x42
	badFeeRecipient := common.TestBuilderSubmitBlockRequestV2(secretkey, bidBadFeeRecipient)

	testCases := []struct {
		description    string
		httpCode       uint64
		simError       error
		overwriteEntry bool
		entry          *blockBuilderCacheEntry
		request        *common.SubmitBlockRequestV2Optimistic
	}{
		{
			description: "success",
			httpCode:    200, // success
			request:     cleanReq,
		},
		{
			description: "failure_malformed_signature",
			httpCode:    400, // failure
			request:     badSigReq,
		},
		{
			description: "failure_invalid_signature",
			httpCode:    400, // failure
			request:     invalidSigReq,
		},
		{
			description:    "failure_no_builder_entry",
			httpCode:       400, // failure
			request:        common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10)),
			entry:          nil,
			overwriteEntry: true,
		},
		{
			description: "failure_builder_not_optimistic",
			httpCode:    400, // failure
			request:     common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10)),
			entry: &blockBuilderCacheEntry{
				status: common.BuilderStatus{
					IsOptimistic: false,
				},
			},
			overwriteEntry: true,
		},
		{
			description: "failure_builder_insufficient_collateral",
			httpCode:    400, // failure
			request:     common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10)),
			entry: &blockBuilderCacheEntry{
				status: common.BuilderStatus{
					IsOptimistic: true,
				},
				collateral: big.NewInt(int64(9)),
			},
			overwriteEntry: true,
		},
		{
			description: "failure_builder_blacklisted",
			httpCode:    200, // we return 200 here.
			request:     common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10)),
			entry: &blockBuilderCacheEntry{
				status: common.BuilderStatus{
					IsOptimistic:  true,
					IsBlacklisted: true,
				},
				collateral: big.NewInt(int64(collateral)),
			},
			overwriteEntry: true,
		},
		{
			description: "failure_bad_time_stamp",
			httpCode:    400, // failure
			request:     badTimestampReq,
		},
		{
			description: "failure_bad_fee_recipient",
			httpCode:    400, // failure
			request:     badFeeRecipient,
		},
		{
			description: "failure_bad_withdrawals_root",
			httpCode:    400, // failure
			request:     badWithdrawalsRootReq,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			backend := startTestBackend(t, pubkey)
			backend.relay.optimisticSlot.Store(slot)
			backend.relay.capellaEpoch = 1
			var randaoHash boostTypes.Hash
			err := randaoHash.FromSlice([]byte(randao))
			require.NoError(t, err)
			withRoot, err := ComputeWithdrawalsRoot([]*consensuscapella.Withdrawal{})
			require.NoError(t, err)
			backend.relay.payloadAttributes[emptyHash] = payloadAttributesHelper{
				slot:            slot,
				withdrawalsRoot: withRoot,
				payloadAttributes: beaconclient.PayloadAttributes{
					PrevRandao: randaoHash.String(),
				},
			}

			if tc.overwriteEntry {
				if tc.entry == nil {
					delete(backend.relay.blockBuildersCache, pubkey.String())
				} else {
					backend.relay.blockBuildersCache[pubkey.String()] = tc.entry
				}
			}

			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
				simulationError: tc.simError,
			}

			outBytes, err := tc.request.MarshalSSZ()
			require.NoError(t, err)

			// Check http code.
			rr := backend.requestBytes(http.MethodPost, pathSubmitNewBlockV2, outBytes, map[string]string{})
			require.Equal(t, uint64(rr.Code), tc.httpCode)
		})
	}
}

func TestBuilderApiOptimisticV2SlowPath_fail_ssz_decode_header(t *testing.T) {
	pubkey, _ := generateKeyPair(t)
	backend := startTestBackend(t, pubkey)
	outBytes := make([]byte, 944) // 944 bytes is min required to try ssz decoding.
	outBytes[0] = 0xaa

	r := bytes.NewReader(outBytes)

	backend.relay.optimisticV2SlowPath(r, v2SlowPathOpts{
		payload: &common.BuilderSubmitBlockRequest{
			Capella: &capella.SubmitBlockRequest{
				Message: &v1.BidTrace{
					BuilderPubkey: *pubkey,
				},
			},
		},
	})

	// Check that demotion occurred.
	mockDB, ok := backend.relay.db.(*database.MockDB)
	require.True(t, ok)
	require.Equal(t, mockDB.Demotions[pubkey.String()], true)
}

func TestBuilderApiOptimisticV2SlowPath(t *testing.T) {
	pubkey, secretkey := generateKeyPair(t)

	testReq := common.TestBuilderSubmitBlockRequestV2(secretkey, getTestBidTrace(*pubkey, 10))
	testPayload := &common.BuilderSubmitBlockRequest{
		Capella: &capella.SubmitBlockRequest{
			Message: &v1.BidTrace{
				BuilderPubkey: *pubkey,
			},
			ExecutionPayload: &consensuscapella.ExecutionPayload{},
		},
	}

	testCases := []struct {
		description    string
		simError       error
		expectDemotion bool
	}{
		{
			description: "success",
		},
		{
			description:    "failure_empty_payload",
			simError:       errFake,
			expectDemotion: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			backend := startTestBackend(t, pubkey)
			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
				simulationError: tc.simError,
			}

			submissionBytes, err := testReq.MarshalSSZ()
			require.NoError(t, err)

			r := bytes.NewReader(submissionBytes)

			opts := v2SlowPathOpts{
				payload: testPayload,
				entry:   &blockBuilderCacheEntry{},
			}
			backend.relay.optimisticV2SlowPath(r, opts)

			// Check demotion status.
			mockDB, ok := backend.relay.db.(*database.MockDB)
			require.True(t, ok)
			require.Equal(t, mockDB.Demotions[pubkey.String()], tc.expectDemotion)
		})
	}
}
