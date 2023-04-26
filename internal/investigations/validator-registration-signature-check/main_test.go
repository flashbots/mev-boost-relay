package main

import (
	"testing"

	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

func TestSignature(t *testing.T) {
	t.Skip()
	pubkey := ""
	gasLimit := 30000000
	feeRecipient := ""
	timestamp := 0
	signature := ""

	_pk, err := boostTypes.HexToPubkey(pubkey)
	require.NoError(t, err)
	_sig, err := boostTypes.HexToSignature(signature)
	require.NoError(t, err)
	_feeRecipient, err := boostTypes.HexToAddress(feeRecipient)
	require.NoError(t, err)

	payload := boostTypes.SignedValidatorRegistration{
		Message: &boostTypes.RegisterValidatorRequestMessage{
			FeeRecipient: _feeRecipient,
			GasLimit:     uint64(gasLimit),
			Timestamp:    uint64(timestamp),
			Pubkey:       _pk,
		},
		Signature: _sig,
	}

	mainnetDetails, err := common.NewEthNetworkDetails(common.EthNetworkMainnet)
	require.NoError(t, err)

	ok, err := boostTypes.VerifySignature(payload.Message, mainnetDetails.DomainBuilder, payload.Message.Pubkey[:], payload.Signature[:])
	require.NoError(t, err)
	require.True(t, ok)
}
