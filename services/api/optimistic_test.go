package api

import (
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
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/utils"
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
	randao      = "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
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
		BidTrace: apiv1.BidTrace{
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
	domain     phase0.Domain
}

func startTestBackend(t *testing.T) (*phase0.BLSPubKey, *bls.SecretKey, *testBackend) {
	t.Helper()
	// Setup test key pair.
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	blsPubkey, err := bls.PublicKeyFromSecretKey(sk)
	require.NoError(t, err)
	pubkey, err := utils.BlsPublicKeyToPublicKey(blsPubkey)
	require.NoError(t, err)
	pkStr := pubkey.String()

	// Setup test backend.
	backend := newTestBackend(t, 1)
	backend.relay.genesisInfo = &beaconclient.GetGenesisResponse{}
	backend.relay.genesisInfo.Data.GenesisTime = 0
	backend.relay.proposerDutiesMap = map[uint64]*common.BuilderGetValidatorsResponseEntry{
		slot: {
			Entry: &apiv1.SignedValidatorRegistration{
				Message: &apiv1.ValidatorRegistration{
					FeeRecipient: [20]byte(feeRecipient),
					GasLimit:     5000,
					Timestamp:    time.Unix(0xffffffff, 0),
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

	backend.relay.headSlot.Store(40)
	return &pubkey, sk, backend
}

func runOptimisticBlockSubmission(t *testing.T, opts blockRequestOpts, simErr error, backend *testBackend) *httptest.ResponseRecorder {
	t.Helper()
	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
		simulationError: simErr,
	}

	req := common.TestBuilderSubmitBlockRequest(opts.secretkey, getTestBidTrace(opts.pubkey, opts.blockValue))
	rr := backend.request(http.MethodPost, pathSubmitNewBlock, req.Capella)

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
			pubkey, secretkey, backend := startTestBackend(t)
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
					VersionedSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
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
			pubkey, secretkey, backend := startTestBackend(t)
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
					VersionedSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
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
	pubkey, secretkey, backend := startTestBackend(t)
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
	pubkey, _, backend := startTestBackend(t)
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
			pubkey, secretkey, backend := startTestBackend(t)
			backend.relay.optimisticSlot.Store(slot)
			backend.relay.capellaEpoch = 1

			randaoHash, err := utils.HexToHash(randao)
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
	pubkey, _, backend := startTestBackend(t)
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
	pubkey, _, backend := startTestBackend(t)
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
