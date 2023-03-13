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
	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	v1 "github.com/attestantio/go-builder-client/api/v1"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
)

const (
	slot        = uint64(41)
	collateral  = 1000
	builderID   = "builder0x69"
	randao      = "01234567890123456789012345678901"
	proposerInd = uint64(987)
)

var (
	feeRecipient = bellatrix.ExecutionAddress{0x02}
	errFake      = fmt.Errorf("foo error")
)

func getTestBlockHash(t *testing.T) boostTypes.Hash {
	var blockHash boostTypes.Hash
	err := blockHash.FromSlice([]byte("98765432109876543210987654321098"))
	require.NoError(t, err)
	return blockHash
}

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
	secretkey  *blst.SecretKey
	blockValue uint64
	domain     boostTypes.Domain
}

func startTestBackend(t *testing.T) (*phase0.BLSPubKey, *blst.SecretKey, *testBackend) {
	// Setup test key pair.
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	blsPubkey := bls.PublicKeyFromSecretKey(sk)
	pkSlice := blsPubkey.Compress()
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], pkSlice[:])
	pkStr := pubkey.String()

	// Setup test backend.
	backend := newTestBackend(t, 1)
	var randaoHash boostTypes.Hash
	err = randaoHash.FromSlice([]byte(randao))
	require.NoError(t, err)
	backend.relay.expectedPrevRandao = randaoHelper{
		slot:       slot,
		prevRandao: randaoHash.String(),
	}
	withRoot, err := ComputeWithdrawalsRoot([]*consensuscapella.Withdrawal{})
	require.NoError(t, err)
	backend.relay.expectedWithdrawalsRoot = withdrawalsHelper{
		slot: slot,
		root: withRoot,
	}
	backend.relay.genesisInfo = &beaconclient.GetGenesisResponse{}
	backend.relay.genesisInfo.Data.GenesisTime = 0
	backend.relay.proposerDutiesMap = map[uint64]*boostTypes.RegisterValidatorRequestMessage{
		slot: {
			FeeRecipient: [20]byte(feeRecipient),
			GasLimit:     5000,
			Timestamp:    0xffffffff,
			Pubkey:       [48]byte(phase0.BLSPubKey{}),
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
	mockRedis, err := datastore.NewRedisCache(redisTestServer.Addr(), "")
	require.NoError(t, err)
	mockDS, err := datastore.NewDatastore(backend.relay.log, mockRedis, mockDB)
	require.NoError(t, err)

	backend.relay.datastore = mockDS
	backend.relay.redis = mockRedis
	backend.relay.db = mockDB

	// Prepare redis.
	err = backend.relay.redis.SetStats(datastore.RedisStatsFieldSlotLastPayloadDelivered, slot-1)
	require.NoError(t, err)
	err = backend.relay.redis.SetKnownValidator(boostTypes.NewPubkeyHex(pubkey.String()), proposerInd)
	require.NoError(t, err)
	comResp := &common.GetPayloadResponse{
		Capella: &api.VersionedExecutionPayload{
			Version: consensusspec.DataVersionCapella,
			Capella: &consensuscapella.ExecutionPayload{
				Transactions: []bellatrix.Transaction{},
			},
		},
	}
	err = backend.relay.redis.SaveExecutionPayload(
		slot,
		pkStr,
		getTestBlockHash(t).String(),
		comResp,
	)
	require.NoError(t, err)
	err = backend.relay.redis.SaveBidTrace(&common.BidTraceV2{
		BidTrace: v1.BidTrace{
			Slot:           slot,
			ProposerPubkey: pubkey,
			BlockHash:      phase0.Hash32(getTestBlockHash(t)),
			BuilderPubkey:  pubkey,
			Value:          uint256.NewInt(5),
		},
	})
	require.NoError(t, err)

	count, err := backend.relay.datastore.RefreshKnownValidators()
	require.NoError(t, err)
	require.Equal(t, count, 1)

	go backend.relay.StartServer() //nolint:errcheck
	time.Sleep(100 * time.Millisecond)
	backend.relay.headSlot.Store(40)

	return &pubkey, sk, backend
}

func runOptimisticGetPayload(t *testing.T, opts blockRequestOpts, backend *testBackend) {
	var txn hexutil.Bytes
	err := txn.UnmarshalText([]byte("0x03"))
	require.NoError(t, err)

	block := &boostTypes.BlindedBeaconBlock{
		Slot:          slot,
		ProposerIndex: proposerInd,
		Body: &boostTypes.BlindedBeaconBlockBody{
			ExecutionPayloadHeader: &boostTypes.ExecutionPayloadHeader{
				BlockHash:   getTestBlockHash(t),
				BlockNumber: 1234,
			},
			Eth1Data:      &boostTypes.Eth1Data{},
			SyncAggregate: &boostTypes.SyncAggregate{},
		},
	}
	signature, err := boostTypes.SignMessage(block, opts.domain, opts.secretkey)
	require.NoError(t, err)
	req := &boostTypes.SignedBlindedBeaconBlock{
		Message:   block,
		Signature: signature,
	}

	rr := backend.request(http.MethodPost, pathGetPayload, req)
	require.Equal(t, rr.Code, http.StatusOK)

	// Let updates happen async.
	time.Sleep(100 * time.Millisecond)
}

func runOptimisticBlockSubmission(t *testing.T, opts blockRequestOpts, simErr error, backend *testBackend) *httptest.ResponseRecorder {
	backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
		simulationError: simErr,
	}

	req := common.TestBuilderSubmitBlockRequest(&opts.pubkey, opts.secretkey, getTestBidTrace(opts.pubkey, opts.blockValue))
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
			simulationError: fmt.Errorf(ErrBlockAlreadyKnown),
		},
		{
			description:     "missing_trie_node",
			simulationError: fmt.Errorf(ErrMissingTrieNode + "23e21f94cd97b3b27ae5c758277639dd387a6e3da5923c5485f24ec6c71e16b8 (path ) <nil>"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.description, func(t *testing.T) {
			pubkey, secretkey, backend := startTestBackend(t)
			backend.relay.blockSimRateLimiter = &MockBlockSimulationRateLimiter{
				simulationError: tc.simulationError,
			}
			err := backend.relay.simulateBlock(context.Background(), blockSimOptions{
				isHighPrio: true,
				log:        backend.relay.log,
				req: &BuilderBlockValidationRequest{
					BuilderSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
						pubkey, secretkey, getTestBidTrace(*pubkey, collateral)),
				},
			})
			if tc.expectError {
				require.Equal(t, tc.simulationError, err)
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
			backend.relay.processOptimisticBlock(context.Background(), blockSimOptions{
				isHighPrio: true,
				log:        backend.relay.log,
				req: &BuilderBlockValidationRequest{
					BuilderSubmitBlockRequest: common.TestBuilderSubmitBlockRequest(
						pubkey, secretkey, getTestBidTrace(*pubkey, collateral)),
				},
			})

			// Check status in db.
			builder, err := backend.relay.db.GetBlockBuilderByPubkey(pkStr)
			require.NoError(t, err)
			require.Equal(t, tc.wantStatus.IsOptimistic, builder.IsOptimistic)
			require.Equal(t, tc.wantStatus.IsHighPrio, builder.IsHighPrio)

			// Check demotion but no refund.
			if tc.simulationError != nil {
				mockDB := backend.relay.db.(*database.MockDB)
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
	req := common.TestBuilderSubmitBlockRequest(pubkey, secretkey, getTestBidTrace(*pubkey, collateral))
	backend.relay.demoteBuilder(pkStr, &req, errFake)

	// Check status in db.
	builder, err := backend.relay.db.GetBlockBuilderByPubkey(pkStr)
	require.NoError(t, err)
	require.Equal(t, wantStatus.IsOptimistic, builder.IsOptimistic)
	require.Equal(t, wantStatus.IsHighPrio, builder.IsHighPrio)

	// Check demotion and refund statuses.
	mockDB := backend.relay.db.(*database.MockDB)
	require.True(t, mockDB.Demotions[pkStr])
}

func TestUpdateOptimisticSlot(t *testing.T) {
	pubkey, _, backend := startTestBackend(t)
	pkStr := pubkey.String()
	// Clear cache.
	backend.relay.blockBuildersCache = map[string]*blockBuilderCacheEntry{}
	backend.relay.updateOptimisticSlot(slot + 1)
	entry, ok := backend.relay.blockBuildersCache[pkStr]
	require.True(t, ok)
	require.Equal(t, true, entry.status.IsHighPrio)
	require.Equal(t, true, entry.status.IsOptimistic)
	require.Equal(t, false, entry.status.IsBlacklisted)
	require.Zero(t, entry.collateral.Cmp(big.NewInt(int64(collateral))))
}

func TestProposerApiGetPayloadOptimistic(t *testing.T) {
	testCases := []struct {
		description string
		wantStatus  common.BuilderStatus
		demoted     bool
	}{
		{
			description: "success",
			wantStatus: common.BuilderStatus{
				IsOptimistic: true,
				IsHighPrio:   true,
			},
			demoted: false,
		},
		{
			description: "sim_error_refund",
			wantStatus: common.BuilderStatus{
				IsOptimistic: false,
				IsHighPrio:   true,
			},
			demoted: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			pubkey, secretkey, backend := startTestBackend(t)
			pkStr := pubkey.String()
			// First insert a demotion.
			if tc.demoted {
				err := backend.relay.db.InsertBuilderDemotion(&common.BuilderSubmitBlockRequest{
					Capella: &capella.SubmitBlockRequest{
						Message: &v1.BidTrace{
							BuilderPubkey: *pubkey,
						},
					},
				}, errFake)
				require.NoError(t, err)
			}

			runOptimisticGetPayload(t, blockRequestOpts{
				secretkey: secretkey,
				pubkey:    *pubkey,
				domain:    backend.relay.opts.EthNetDetails.DomainBeaconProposerCapella,
			}, backend)

			// Check demotion and refund status'.
			mockDB := backend.relay.db.(*database.MockDB)
			require.Equal(t, tc.demoted, mockDB.Demotions[pkStr])
			require.Equal(t, tc.demoted, mockDB.Refunds[pkStr])
		})
	}
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
			description: "failure_value_less_than_collateral",
			wantStatus: common.BuilderStatus{
				IsOptimistic: false,
				IsHighPrio:   true,
			},
			simulationError: errFake,
			expectDemotion:  true,
			httpCode:        200, // success (in optimistic mode, block sim failure will happen async)
			blockValue:      collateral - 1,
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
			backend.relay.optimisticSlot = slot
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
			mockDB := backend.relay.db.(*database.MockDB)
			require.Equal(t, mockDB.Demotions[pkStr], tc.expectDemotion)
			require.False(t, mockDB.Refunds[pkStr])
		})
	}
}

func TestInternalBuilderStatus(t *testing.T) {
	pubkey, _, backend := startTestBackend(t)
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
	setAndGetStatus("?high_prio=true", common.BuilderStatus{IsHighPrio: true})
	setAndGetStatus("?blacklisted=true", common.BuilderStatus{IsBlacklisted: true})
	setAndGetStatus("?optimistic=true", common.BuilderStatus{IsOptimistic: true})
	setAndGetStatus("", common.BuilderStatus{})
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
