package common

import (
	"testing"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func makeTestSubmitBlockRequestV2Optimistic(t *testing.T) *SubmitBlockRequestV2Optimistic {
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

	return &SubmitBlockRequestV2Optimistic{
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
		ExecutionPayloadHeader: &capella.ExecutionPayloadHeader{
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
			BaseFeePerGas:    [32]byte{0xaa, 0xbb},
			BlockHash:        testBlockHash,
			TransactionsRoot: phase0.Root(testRoot),
			WithdrawalsRoot:  phase0.Root(testRoot),
		},
		Signature: testSignature,
		Transactions: []bellatrix.Transaction{
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			[]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19},
			[]byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29},
			[]byte{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39},
			[]byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49},
			[]byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59},
		},
		Withdrawals: []*capella.Withdrawal{
			{
				Index:          capella.WithdrawalIndex(120),
				ValidatorIndex: phase0.ValidatorIndex(121),
				Address:        testAddress,
				Amount:         phase0.Gwei(102412521125125),
			},
		},
	}
}

func TestDataVersion(t *testing.T) {
	require.Equal(t, ForkVersionStringBellatrix, spec.DataVersionBellatrix.String())
	require.Equal(t, ForkVersionStringCapella, spec.DataVersionCapella.String())
	require.Equal(t, ForkVersionStringDeneb, spec.DataVersionDeneb.String())
}

func compareV2RequestEquality(t *testing.T, src, targ *SubmitBlockRequestV2Optimistic) {
	t.Helper()
	require.Equal(t, src.Message.String(), targ.Message.String())
	require.Equal(t, src.ExecutionPayloadHeader.String(), targ.ExecutionPayloadHeader.String())
	require.Equal(t, src.Signature, targ.Signature)
	for i := 0; i < len(src.Transactions); i++ {
		require.Equal(t, src.Transactions[i], targ.Transactions[i])
	}
	for i := 0; i < len(src.Withdrawals); i++ {
		require.Equal(t, src.Withdrawals[i].String(), targ.Withdrawals[i].String())
	}
}

func TestSubmitBlockRequestV2Optimistic(t *testing.T) {
	obj := makeTestSubmitBlockRequestV2Optimistic(t)

	// Encode the object.
	sszObj, err := obj.MarshalSSZ()
	require.NoError(t, err)
	require.Len(t, sszObj, obj.SizeSSZ())

	// Unmarshal the full object.
	unmarshal := new(SubmitBlockRequestV2Optimistic)
	err = unmarshal.UnmarshalSSZ(sszObj)
	require.NoError(t, err)

	compareV2RequestEquality(t, obj, unmarshal)

	// Clear out non-header data.
	obj.Transactions = []bellatrix.Transaction{}
	obj.Withdrawals = []*capella.Withdrawal{}

	// Unmarshal just the header.
	unmarshalHeader := new(SubmitBlockRequestV2Optimistic)
	err = unmarshalHeader.UnmarshalSSZHeaderOnly(sszObj)
	require.NoError(t, err)

	compareV2RequestEquality(t, obj, unmarshalHeader)

	// Make sure size is correct (must have 32 bytes of ExtraData).
	require.Equal(t, 944, unmarshalHeader.SizeSSZ())
}
