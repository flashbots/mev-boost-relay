package api

import (
	"testing"

	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestBuilderBlockRequestToSignedBuilderBid(t *testing.T) {
	builderPk, err := utils.HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
	require.NoError(t, err)

	builderSk, err := utils.HexToSignature("0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea")
	require.NoError(t, err)

	cases := []struct {
		name       string
		reqPayload *common.VersionedSubmitBlockRequest
	}{
		{
			name: "Capella",
			reqPayload: &common.VersionedSubmitBlockRequest{
				VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
					Version: spec.DataVersionCapella,
					Capella: &builderApiCapella.SubmitBlockRequest{
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
						Message: &builderApiV1.BidTrace{
							Slot:                 1,
							ParentHash:           phase0.Hash32{0x01},
							BlockHash:            phase0.Hash32{0x09},
							BuilderPubkey:        builderPk,
							ProposerPubkey:       phase0.BLSPubKey{0x03},
							ProposerFeeRecipient: bellatrix.ExecutionAddress{0x04},
							Value:                uint256.NewInt(123),
							GasLimit:             5002,
							GasUsed:              5003,
						},
						Signature: builderSk,
					},
				},
			},
		},
		{
			name: "Deneb",
			reqPayload: &common.VersionedSubmitBlockRequest{
				VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
					Version: spec.DataVersionDeneb,
					Deneb: &builderApiDeneb.SubmitBlockRequest{
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
						Message: &builderApiV1.BidTrace{
							Slot:                 1,
							ParentHash:           phase0.Hash32{0x01},
							BlockHash:            phase0.Hash32{0x09},
							BuilderPubkey:        builderPk,
							ProposerPubkey:       phase0.BLSPubKey{0x03},
							ProposerFeeRecipient: bellatrix.ExecutionAddress{0x04},
							Value:                uint256.NewInt(123),
							GasLimit:             5002,
							GasUsed:              5003,
						},
						Signature: builderSk,
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sk, _, err := bls.GenerateNewKeypair()
			require.NoError(t, err)

			pubkey, err := bls.PublicKeyFromSecretKey(sk)
			require.NoError(t, err)

			publicKey, err := utils.BlsPublicKeyToPublicKey(pubkey)
			require.NoError(t, err)

			signedBuilderBid, err := common.BuildGetHeaderResponse(tc.reqPayload, sk, &publicKey, ssz.DomainBuilder)
			require.NoError(t, err)

			bidValue, err := signedBuilderBid.Value()
			require.NoError(t, err)
			respValue, err := tc.reqPayload.Value()
			require.NoError(t, err)

			bidHash, err := signedBuilderBid.BlockHash()
			require.NoError(t, err)
			respHash, err := tc.reqPayload.BlockHash()
			require.NoError(t, err)

			require.Equal(t, 0, bidValue.Cmp(respValue))
			require.Equal(t, respHash, bidHash)
		})
	}
}
