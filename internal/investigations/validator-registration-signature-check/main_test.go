package main

import (
	"testing"

	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

// TestValidatorRegistrationSignature can be used to validate the signature of an arbitrary validator registration
func TestValidatorRegistrationSignature(t *testing.T) {
	t.Skip()

	// Fill in validator registration details
	pubkey := ""
	gasLimit := 30000000
	feeRecipient := ""
	timestamp := 0
	signature := ""

	// Constructing the object
	payload := boostTypes.SignedValidatorRegistration{
		Message: &boostTypes.RegisterValidatorRequestMessage{
			GasLimit:  uint64(gasLimit),
			Timestamp: uint64(timestamp),
		},
	}

	var err error
	payload.Message.Pubkey, err = boostTypes.HexToPubkey(pubkey)
	require.NoError(t, err)
	payload.Signature, err = boostTypes.HexToSignature(signature)
	require.NoError(t, err)
	payload.Message.FeeRecipient, err = boostTypes.HexToAddress(feeRecipient)
	require.NoError(t, err)

	mainnetDetails, err := common.NewEthNetworkDetails(common.EthNetworkMainnet)
	require.NoError(t, err)

	ok, err := boostTypes.VerifySignature(payload.Message, mainnetDetails.DomainBuilder, payload.Message.Pubkey[:], payload.Signature[:])
	require.NoError(t, err)
	require.True(t, ok)
}
