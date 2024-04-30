package common

import (
	"testing"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func makeTestVersionedSubmitHeaderOptimistic(t *testing.T) *VersionedSubmitHeaderOptimistic {
	t.Helper()
	testParentHash, err := utils.HexToHash("0xec51bd499a3fa0270f1446fbf05ff0b61157cfe4ec719bb4c3e834e339ee9c5c")
	require.NoError(t, err)
	testBlockHash, err := utils.HexToHash("0x3f5b5aaa800a3d25c3f75e72dc45da89fdd58168f1358a9f94aac8b029361a0a")
	require.NoError(t, err)
	testRandao, err := utils.HexToHash("0x8cf6b7fbfbaf80da001fe769fd02e9b8dbfa0a646d9cf51b5d7137dd4f8103cc")
	require.NoError(t, err)
	testRoot, err := utils.HexToHash("0x7554727cee6d976a1dfdad80b392b37c87f0651ff5b01f6a0b3402bcfce92077")
	require.NoError(t, err)
	testBuilderPubkey, err := utils.HexToPubkey("0xae7bde4839fa905b7d8125fd84cfdcd0c32cd74e1be3fa24263d71b520fc78113326ce0a90b95d73f19e6d8150a2f73b")
	require.NoError(t, err)
	testProposerPubkey, err := utils.HexToPubkey("0xbb8e223239fa905b7d8125fd84cfdcd0c32cd74e1be3fa24263d71b520fc78113326ce0a90b95d73f19e6d8150a2f73b")
	require.NoError(t, err)
	testAddress, err := utils.HexToAddress("0x95222290DD7278Aa3Ddd389Cc1E1d165CC4BAfe5")
	require.NoError(t, err)
	testSignature, err := utils.HexToSignature("0xb06311be19c92307c06070578af9ad147c9c6ea902439eac19f785f3dca478c354b79a0af9b09839c3d06c1ccf2185b0162f4d4fbf981220f77586b52ed9ae8a8acfc953baaa30dee15e1b112913c6cbe02c780d7b5363a4af16563fe55c2e88")
	require.NoError(t, err)
	testValue := new(uint256.Int)
	err = testValue.SetFromDecimal("100")
	require.NoError(t, err)

	return &VersionedSubmitHeaderOptimistic{
		Version: spec.DataVersionDeneb,
		Deneb: &DenebSubmitHeaderOptimistic{
			Message: &builderApiV1.BidTrace{
				Slot:                 31,
				ParentHash:           testParentHash,
				BlockHash:            testBlockHash,
				BuilderPubkey:        testBuilderPubkey,
				ProposerPubkey:       testProposerPubkey,
				ProposerFeeRecipient: testAddress,
				GasLimit:             30_000_000,
				GasUsed:              15_000_000,
				Value:                testValue,
			},
			ExecutionPayloadHeader: &deneb.ExecutionPayloadHeader{
				ParentHash:       testParentHash,
				FeeRecipient:     testAddress,
				StateRoot:        [32]byte(testBlockHash),
				ReceiptsRoot:     [32]byte(testBlockHash),
				LogsBloom:        [256]byte{0xaa, 0xbb, 0xcc},
				PrevRandao:       [32]byte(testRandao),
				BlockNumber:      30,
				GasLimit:         30_000_000,
				GasUsed:          15_000_000,
				Timestamp:        168318215,
				ExtraData:        make([]byte, 32),
				BaseFeePerGas:    uint256.NewInt(100),
				BlockHash:        testBlockHash,
				TransactionsRoot: phase0.Root(testRoot),
				WithdrawalsRoot:  phase0.Root(testRoot),
				BlobGasUsed:      15_000_000,
				ExcessBlobGas:    30_000_000,
			},
			Signature: testSignature,
		},
	}
}

func TestDataVersion(t *testing.T) {
	require.Equal(t, ForkVersionStringBellatrix, spec.DataVersionBellatrix.String())
	require.Equal(t, ForkVersionStringCapella, spec.DataVersionCapella.String())
	require.Equal(t, ForkVersionStringDeneb, spec.DataVersionDeneb.String())
}

func compareV2RequestEquality(t *testing.T, src, targ *VersionedSubmitHeaderOptimistic) {
	t.Helper()
	srcBidTrace, err := src.BidTrace()
	require.NoError(t, err)
	targBidTrace, err := targ.BidTrace()
	require.NoError(t, err)
	require.Equal(t, srcBidTrace, targBidTrace)
	srcBlockHash, err := src.ExecutionPayloadBlockHash()
	require.NoError(t, err)
	targBlockHash, err := targ.ExecutionPayloadBlockHash()
	require.NoError(t, err)
	require.Equal(t, srcBlockHash, targBlockHash)
	srcSignature, err := src.Signature()
	require.NoError(t, err)
	targSignature, err := targ.Signature()
	require.NoError(t, err)
	require.Equal(t, srcSignature, targSignature)
}

func TestSubmitBlockHeaderV2Optimistic(t *testing.T) {
	obj := makeTestVersionedSubmitHeaderOptimistic(t)

	// Encode the object.
	sszObj, err := obj.MarshalSSZ()
	require.NoError(t, err)
	require.Len(t, sszObj, 956)

	// Unmarshal the header.
	unmarshal := new(VersionedSubmitHeaderOptimistic)
	err = unmarshal.UnmarshalSSZ(sszObj)
	require.NoError(t, err)

	compareV2RequestEquality(t, obj, unmarshal)

	// Add KZG data.
	obj.Deneb.BlobKZGCommitments = make([]deneb.KZGCommitment, 1)
	sszObj, err = obj.MarshalSSZ()
	require.NoError(t, err)

	// Make sure size is correct (must have 48 extra bytes from KZG commitments).
	require.Len(t, sszObj, 1004)
}
