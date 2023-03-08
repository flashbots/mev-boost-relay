package datastore

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// TODO: standardize integration tests to run with single flag/env var - consolidate with RUN_DB_TESTS
var (
	runIntegrationTests = os.Getenv("RUN_INTEGRATION_TESTS") == "1"
	memcachedEndpoints  = common.GetSliceEnv("MEMCACHED_ENDPOINTS", nil)
)

func initMemcached(t *testing.T) (mem *Memcached, err error) {
	t.Helper()
	if !runIntegrationTests {
		t.Skip("Skipping integration tests for memcached")
	}

	mem, err = NewMemcached("test", memcachedEndpoints...)
	if err != nil {
		return
	}

	// reset cache to avoid conflicts between tests
	err = mem.client.DeleteAll()
	return
}

func TestMemcached(t *testing.T) {
	type test struct {
		Input       common.BuilderSubmitBlockRequest
		Description string
		TestSuite   func(tc *test) func(*testing.T)
	}

	mem, err := initMemcached(t)
	require.NoError(t, err)
	require.NotNil(t, mem)

	builderPk, err := types.HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
	require.NoError(t, err)

	builderSk, err := types.HexToSignature("0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea")
	require.NoError(t, err)

	testCases := []test{
		{
			Description: "Given an invalid execution payload, we expect an invalid payload error when attempting to create a payload response",
			Input: common.BuilderSubmitBlockRequest{
				Bellatrix: nil,
				Capella:   nil,
			},
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					payload, err := tc.Input.ExecutionPayloadResponse()
					require.Error(t, err)
					require.Equal(t, err, common.ErrEmptyPayload)
					require.Nil(t, payload)
				}
			},
		},
		{
			Description: "Given an invalid proposer public key, we expect an invalid key error when storing and fetching the item in memcached",
			Input: common.BuilderSubmitBlockRequest{
				Bellatrix: &types.BuilderSubmitBlockRequest{
					Signature: builderSk,
					Message: &types.BidTrace{
						Slot:          1,
						ParentHash:    types.Hash{0x01},
						BlockHash:     types.Hash{0x09},
						BuilderPubkey: builderPk,
					},
					ExecutionPayload: &types.ExecutionPayload{
						BlockHash: types.Hash{0x09},
					},
				},
			},
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					payload, _ := tc.Input.ExecutionPayloadResponse()
					err := mem.SaveExecutionPayload(tc.Input.Slot(), "", tc.Input.BlockHash(), payload)
					require.Error(t, err)
					require.Equal(t, err, ErrInvalidProposerPublicKey)

					_, err = mem.GetExecutionPayload(tc.Input.Slot(), "", tc.Input.BlockHash())
					require.Error(t, err)
					require.Equal(t, err, ErrInvalidProposerPublicKey)
				}
			},
		},
		{
			Description: "Given an invalid block hash, we expect an invalid block hash error when storing and fetching the item in memcached",
			Input: common.BuilderSubmitBlockRequest{
				Bellatrix: &types.BuilderSubmitBlockRequest{
					Signature: builderSk,
					Message: &types.BidTrace{
						Slot:          1,
						ParentHash:    types.Hash{0x01},
						BuilderPubkey: builderPk,
					},
					ExecutionPayload: &types.ExecutionPayload{},
				},
			},
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
					payload, _ := tc.Input.ExecutionPayloadResponse()
					err := mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), "", payload)
					require.Error(t, err)
					require.Equal(t, err, ErrInvalidBlockHash)

					_, err = mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), "")
					require.Error(t, err)
					require.Equal(t, err, ErrInvalidBlockHash)
				}
			},
		},
		{
			Description: "Given a valid builder submit block request, we expect to successfully store and retrieve the value from memcached",
			Input: common.BuilderSubmitBlockRequest{
				Bellatrix: &types.BuilderSubmitBlockRequest{
					Signature: builderSk,
					Message: &types.BidTrace{
						Slot:                 1,
						ParentHash:           types.Hash{0x01},
						BlockHash:            types.Hash{0x09},
						BuilderPubkey:        builderPk,
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
			},
			TestSuite: func(tc *test) func(*testing.T) {
				return func(t *testing.T) {
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

					err = mem.SaveExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash(), payload)
					require.NoError(t, err)

					get, err := mem.GetExecutionPayload(tc.Input.Slot(), tc.Input.ProposerPubkey(), tc.Input.BlockHash())
					require.NoError(t, err, "expected no error when fetching execution payload from memcached but found [%v]", err)

					getBytes, err := get.MarshalJSON()
					require.NoError(t, err)
					require.True(t, bytes.Equal(outputBytes, getBytes))
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Description, tc.TestSuite(&tc))
	}
}
