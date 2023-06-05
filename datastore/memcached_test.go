package datastore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

// TODO: standardize integration tests to run with single flag/env var - consolidate with RUN_DB_TESTS
var (
	runIntegrationTests = os.Getenv("RUN_INTEGRATION_TESTS") == "1"
	memcachedEndpoints  = common.GetSliceEnv("MEMCACHED_URIS", nil)

	ErrNoMemcachedServers = errors.New("no memcached servers specified")
)

func testBuilderSubmitBlockRequest(pubkey types.PublicKey, signature types.Signature, version consensusspec.DataVersion) common.BuilderSubmitBlockRequest {
	switch version {
	case consensusspec.DataVersionBellatrix:
		return common.BuilderSubmitBlockRequest{
			Bellatrix: &types.BuilderSubmitBlockRequest{
				Signature: signature,
				Message: &types.BidTrace{
					Slot:                 1,
					ParentHash:           types.Hash{0x01},
					BlockHash:            types.Hash{0x09},
					BuilderPubkey:        pubkey,
					ProposerPubkey:       types.PublicKey{0x03},
					ProposerFeeRecipient: types.Address{0x04},
					Value:                types.IntToU256(123),
					GasLimit:             5002,
					GasUsed:              5003,
				},
				ExecutionPayload: &types.ExecutionPayload{
					ParentHash:    types.Hash{0x01},
					FeeRecipient:  types.Address{0x02},
					StateRoot:     types.Root{0x03},
					ReceiptsRoot:  types.Root{0x04},
					LogsBloom:     types.Bloom{0x05},
					Random:        types.Hash{0x06},
					BlockNumber:   5001,
					GasLimit:      5002,
					GasUsed:       5003,
					Timestamp:     5004,
					ExtraData:     []byte{0x07},
					BaseFeePerGas: types.IntToU256(123),
					BlockHash:     types.Hash{0x09},
					Transactions:  []hexutil.Bytes{},
				},
			},
		}
	case consensusspec.DataVersionDeneb:
		fallthrough
	case consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionCapella:
		fallthrough
	default:
		return common.BuilderSubmitBlockRequest{
			Bellatrix: nil,
			Capella:   nil,
		}
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
		Input       common.BuilderSubmitBlockRequest
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

	builderPk, err := types.HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
	require.NoError(t, err)

	builderSk, err := types.HexToSignature("0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea")
	require.NoError(t, err)

	testCases := []test{
		{
			Description: "Given an invalid execution payload, we expect an invalid payload error when attempting to create a payload response",
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, math.MaxUint64),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()
					payload, err := tc.Input.ExecutionPayloadResponse()
					require.Error(t, err)
					require.Equal(t, err, common.ErrEmptyPayload)
					require.Nil(t, payload)
				}
			},
		},
		{
			Description: "Given a valid builder submit block request, we expect to successfully store and retrieve the value from memcached",
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, consensusspec.DataVersionBellatrix),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()

					payload, err := tc.Input.ExecutionPayloadResponse()
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

					out := new(common.VersionedExecutionPayload)
					err = out.UnmarshalJSON(inputBytes)
					require.NoError(
						t,
						err,
						"expected no error when unmarshalling execution payload response to versioned execution payload but found [%v]", err,
					)

					outputBytes, err := out.MarshalJSON()
					require.NoError(t, err)
					require.True(t, bytes.Equal(inputBytes, outputBytes))

					// key should not exist in cache yet
					empty, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
					require.NoError(t, err)
					require.Nil(t, empty)

					err = mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash(), payload)
					require.NoError(t, err)

					get, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
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
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, consensusspec.DataVersionBellatrix),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()

					payload, err := tc.Input.ExecutionPayloadResponse()
					require.NoError(
						t,
						err,
						"expected valid execution payload response for builder's submit block request but found [%v]", err,
					)

					err = mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash(), payload)
					require.NoError(t, err)

					prev, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
					require.NoError(t, err)
					require.Equal(t, prev.NumTx(), tc.Input.NumTx())

					payload.Bellatrix.Data.GasLimit++
					require.NotEqual(t, prev.Bellatrix.Data.GasLimit, payload.Bellatrix.Data.GasLimit)

					err = mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash(), payload)
					require.NoError(t, err)

					current, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
					require.NoError(t, err)
					require.Equal(t, current.Bellatrix.Data.GasLimit, payload.Bellatrix.Data.GasLimit)
					require.NotEqual(t, current.Bellatrix.Data.GasLimit, prev.Bellatrix.Data.GasLimit)
				}
			},
		},
		{
			Description: fmt.Sprintf("Given a valid builder submit block request, memcached entry should expire after %d seconds", defaultMemcachedExpirySeconds),
			Input:       testBuilderSubmitBlockRequest(builderPk, builderSk, consensusspec.DataVersionBellatrix),
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					t.Helper()
					t.Parallel()

					_, pubkey, err := bls.GenerateNewKeypair()
					require.NoError(t, err)

					pk, err := types.BlsPublicKeyToPublicKey(pubkey)
					require.NoError(t, err)

					tc.Input.Bellatrix.Message.ProposerPubkey = pk
					payload, err := tc.Input.ExecutionPayloadResponse()
					require.NoError(
						t,
						err,
						"expected valid execution payload response for builder's submit block request but found [%v]", err,
					)
					require.Equal(t, tc.Input.ProposerPubkey(), pk.String())

					err = mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash(), payload)
					require.NoError(t, err)

					ret, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
					require.NoError(t, err)
					require.Equal(t, ret.NumTx(), tc.Input.NumTx())

					time.Sleep((time.Duration(defaultMemcachedExpirySeconds) + 2) * time.Second)
					expired, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
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
