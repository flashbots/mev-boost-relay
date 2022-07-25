package api

import (
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestBuilderBlockRequestToSignedBuilderBid(t *testing.T) {
	builderPk, err := types.HexToPubkey("0xf9716c94aab536227804e859d15207aa7eaaacd839f39dcbdb5adc942842a8d2fb730f9f49fc719fdb86f1873e0ed1c2")
	require.NoError(t, err)

	builderSk, err := types.HexToSignature("0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea")
	require.NoError(t, err)

	reqPayload := types.BuilderSubmitBlockRequest{
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
		Message: &types.BidTrace{
			Slot:                 1,
			ParentHash:           types.Hash{0x01},
			BlockHash:            types.Hash{0x09},
			BuilderPubkey:        builderPk,
			ProposerPubkey:       types.PublicKey{0x03},
			ProposerFeeRecipient: types.Address{0x04},
			Value:                types.IntToU256(123),
		},
		Signature: builderSk,
	}

	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)

	publicKey := types.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(sk))

	signedBuilderBid, err := BuilderSubmitBlockRequestToSignedBuilderBid(&reqPayload, sk, &publicKey, builderSigningDomain)
	require.NoError(t, err)

	require.Equal(t, 0, signedBuilderBid.Message.Value.Cmp(&reqPayload.Message.Value))
	require.Equal(t, reqPayload.Message.BlockHash, signedBuilderBid.Message.Header.BlockHash)
}
