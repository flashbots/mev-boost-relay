package datastore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

// TODO: standardize integration tests to run with single flag/env var - consolidate with RUN_DB_TESTS
var (
	runIntegrationTests = os.Getenv("RUN_INTEGRATION_TESTS") == "1"
	memcachedEndpoints  = common.GetSliceEnv("MEMCACHED_URIS", nil)

	ErrNoMemcachedServers = errors.New("no memcached servers specified")
)

func testBuilderSubmitBlockRequest(pubkey phase0.BLSPubKey, signature phase0.BLSSignature, version spec.DataVersion) common.VersionedSubmitBlockRequest {
	switch version { //nolint:exhaustive
	case spec.DataVersionDeneb:
		return common.VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionDeneb,
				Deneb: &builderApiDeneb.SubmitBlockRequest{
					Signature: signature,
					Message: &builderApiV1.BidTrace{
						Slot:                 1,
						ParentHash:           phase0.Hash32{0x01},
						BlockHash:            phase0.Hash32{0x09},
						BuilderPubkey:        pubkey,
						ProposerPubkey:       phase0.BLSPubKey{0x03},
						ProposerFeeRecipient: bellatrix.ExecutionAddress{0x04},
						Value:                uint256.NewInt(123),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					ExecutionPayload: &deneb.ExecutionPayload{
						ParentHash:    phase0.Hash32{0x01},
						FeeRecipient:  bellatrix.ExecutionAddress{0x02},
						StateRoot:     phase0.Root{0x03},
						ReceiptsRoot:  phase0.Root{0x04},
						LogsBloom:     [256]byte{0x05},
						PrevRandao:    phase0.Hash32{0x06},
						BlockNumber:   5001,
						GasLimit:      5002,
						GasUsed:       5003,
						Timestamp:     5004,
						ExtraData:     []byte{0x07},
						BaseFeePerGas: uint256.NewInt(123),
						BlockHash:     phase0.Hash32{0x09},
						Transactions:  []bellatrix.Transaction{},
						BlobGasUsed:   5005,
						ExcessBlobGas: 5006,
					},
					BlobsBundle: &builderApiDeneb.BlobsBundle{
						Commitments: []deneb.KZGCommitment{},
						Proofs:      []deneb.KZGProof{},
						Blobs:       []deneb.Blob{},
					},
				},
			},
		}
	case spec.DataVersionCapella:
		return common.VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionCapella,
				Capella: &builderApiCapella.SubmitBlockRequest{
					Signature: signature,
					Message: &builderApiV1.BidTrace{
						Slot:                 1,
						ParentHash:           phase0.Hash32{0x01},
						BlockHash:            phase0.Hash32{0x09},
						BuilderPubkey:        pubkey,
						ProposerPubkey:       phase0.BLSPubKey{0x03},
						ProposerFeeRecipient: bellatrix.ExecutionAddress{0x04},
						Value:                uint256.NewInt(123),
						GasLimit:             5002,
						GasUsed:              5003,
					},
					ExecutionPayload: &capella.ExecutionPayload{
						ParentHash:    phase0.Hash32{0x01},
						FeeRecipient:  bellatrix.ExecutionAddress{0x02},
						StateRoot:     phase0.Root{0x03},
						ReceiptsRoot:  phase0.Root{0x04},
						LogsBloom:     [256]byte{0x05},
						PrevRandao:    phase0.Hash32{0x06},
						BlockNumber:   5001,
						GasLimit:      5002,
						GasUsed:       5003,
						Timestamp:     5004,
						ExtraData:     []byte{0x07},
						BaseFeePerGas: types.IntToU256(123),
						BlockHash:     phase0.Hash32{0x09},
						Transactions:  []bellatrix.Transaction{},
					},
				},
			},
		}
	default:
		return common.VersionedSubmitBlockRequest{}
	}
}

func initMemcached(t *testing.T) (mem *Memcached, err error) {
	t.Helper()
	if !runIntegrationTests {
		t.Skip("Skipping integration tests for memcached")
	}

	if len(memcachedEndpoints) == 0 {
		err = ErrNoMemcachedServers
		return
	}

	mem, err = NewMemcached("test", memcachedEndpoints...)
	if err != nil {
		return
	}

	// reset cache to avoid conflicts between tests
	err = mem.client.DeleteAll()
	return
}

// TestMemcached performs integration tests when RUN_INTEGRATION_TESTS is true, using
// a comma separated list of endpoints specified by the environment variable MEMCACHED_URIS.
// Example:
//
//	# start memcached docker container locally
//	docker run -d -p 11211:11211 memcached
//	# navigate to mev-boost-relay working directory and run memcached tests
//	RUN_INTEGRATION_TESTS=1 MEMCACHED_URIS="localhost:11211" go test -v -run ".*Memcached.*" ./...
func TestMemcached(t *testing.T) {
	type test struct {
		Input       common.VersionedSubmitBlockRequest
		Description string
		TestSuite   func(tc *test) func(*testing.T)
	}

	var (
		mem *Memcached
		err error
	)

	mem, err = initMemcached(t)
	require.NoError(t, err)
	require.NotNil(t, mem)

	builderPk, err := utils.HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
	require.NoError(t, err)

	builderSk, err := utils.HexToSignature("0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea")
	require.NoError(t, err)

	testCases := []test{
		{
			Description: "Given an invalid execution payload, we expect an invalid payload error when attempting to create a payload response",
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, math.MaxUint64),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()
					payload, err := common.GetBlockSubmissionExecutionPayload(&tc.Input)
					require.Error(t, err)
					require.Equal(t, err, common.ErrEmptyPayload)
					require.Nil(t, payload)
				}
			},
		},
		{
			Description: "Given a valid builder submit block request, we expect to successfully store and retrieve the value from memcached",
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, spec.DataVersionCapella),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()

					payload, err := common.GetBlockSubmissionExecutionPayload(&tc.Input)
					require.NoError(
						t,
						err,
						"expected valid execution payload response for builder's submit block request but found [%v]", err,
					)

					inputBytes, err := payload.MarshalJSON()
					require.NoError(
						t,
						err,
						"expected no error when marshalling execution payload response but found [%v]", err,
					)

					out := new(builderApi.VersionedSubmitBlindedBlockResponse)
					err = out.UnmarshalJSON(inputBytes)
					require.NoError(
						t,
						err,
						"expected no error when unmarshalling execution payload response to versioned execution payload but found [%v]", err,
					)

					outputBytes, err := out.MarshalJSON()
					require.NoError(t, err)
					require.True(t, bytes.Equal(inputBytes, outputBytes))

					submission, err := common.GetBlockSubmissionInfo(&tc.Input)
					require.NoError(t, err)

					// key should not exist in cache yet
					empty, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err)
					require.Nil(t, empty)

					submission, err = common.GetBlockSubmissionInfo(&tc.Input)
					require.NoError(t, err)
					err = mem.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), payload)
					require.NoError(t, err)

					get, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err, "expected no error when fetching execution payload from memcached but found [%v]", err)

					getBytes, err := get.MarshalJSON()
					require.NoError(t, err)
					require.True(t, bytes.Equal(outputBytes, getBytes))
					require.True(t, bytes.Equal(getBytes, inputBytes))
				}
			},
		},
		{
			Description: "Given a valid builder submit block request, updates to the same key should overwrite existing entry and return the last written value",
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, spec.DataVersionDeneb),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()

					payload, err := common.GetBlockSubmissionExecutionPayload(&tc.Input)
					require.NoError(
						t,
						err,
						"expected valid execution payload response for builder's submit block request but found [%v]", err,
					)

					submission, err := common.GetBlockSubmissionInfo(&tc.Input)
					require.NoError(t, err)

					err = mem.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), payload)
					require.NoError(t, err)

					prev, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err)
					require.Equal(t, len(prev.Capella.Transactions), len(submission.Transactions))

					payload.Capella.GasLimit++
					require.NotEqual(t, prev.Capella.GasLimit, payload.Capella.GasLimit)

					err = mem.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), payload)
					require.NoError(t, err)

					current, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err)
					require.Equal(t, current.Capella.GasLimit, payload.Capella.GasLimit)
					require.NotEqual(t, current.Capella.GasLimit, prev.Capella.GasLimit)
				}
			},
		},
		{
			Description: fmt.Sprintf("Given a valid builder submit block request, memcached entry should expire after %d seconds", defaultMemcachedExpirySeconds),
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, spec.DataVersionCapella),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()
					t.Parallel()

					_, pubkey, err := bls.GenerateNewKeypair()
					require.NoError(t, err)

					pk, err := utils.BlsPublicKeyToPublicKey(pubkey)
					require.NoError(t, err)

					tc.Input.Capella.Message.ProposerPubkey = pk
					payload, err := common.GetBlockSubmissionExecutionPayload(&tc.Input)
					require.NoError(
						t,
						err,
						"expected valid execution payload response for builder's submit block request but found [%v]", err,
					)

					submission, err := common.GetBlockSubmissionInfo(&tc.Input)
					require.NoError(t, err)

					require.Equal(t, submission.BidTrace.ProposerPubkey.String(), pk.String())

					err = mem.SaveExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String(), payload)
					require.NoError(t, err)

					ret, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err)
					require.Equal(t, len(ret.Capella.Transactions), len(submission.Transactions))

					time.Sleep((time.Duration(defaultMemcachedExpirySeconds) + 2) * time.Second)
					expired, err := mem.GetExecutionPayload(submission.BidTrace.Slot, submission.BidTrace.ProposerPubkey.String(), submission.BidTrace.BlockHash.String())
					require.NoError(t, err)
					require.NotEqual(t, ret, expired)
					require.Nil(t, expired)
				}
			},
		},
	}

	for _, tc := range testCases {
		testcase := tc
		t.Run(testcase.Description, testcase.TestSuite(&testcase))
	}
}
