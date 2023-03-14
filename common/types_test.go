package common

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestBoostBidToBidTrace(t *testing.T) {
	bidTrace := boostTypes.BidTrace{
		Slot:                 uint64(25),
		ParentHash:           boostTypes.Hash{0x02, 0x03},
		BuilderPubkey:        boostTypes.PublicKey{0x04, 0x05},
		ProposerPubkey:       boostTypes.PublicKey{0x06, 0x07},
		ProposerFeeRecipient: boostTypes.Address{0x08, 0x09},
		GasLimit:             uint64(50),
		GasUsed:              uint64(100),
		Value:                boostTypes.U256Str{0x0a},
	}
	convertedBidTrace := BoostBidToBidTrace(&bidTrace)
	require.Equal(t, bidTrace.Slot, convertedBidTrace.Slot)
	require.Equal(t, phase0.Hash32(bidTrace.ParentHash), convertedBidTrace.ParentHash)
	require.Equal(t, phase0.BLSPubKey(bidTrace.BuilderPubkey), convertedBidTrace.BuilderPubkey)
	require.Equal(t, phase0.BLSPubKey(bidTrace.ProposerPubkey), convertedBidTrace.ProposerPubkey)
	require.Equal(t, bellatrix.ExecutionAddress(bidTrace.ProposerFeeRecipient), convertedBidTrace.ProposerFeeRecipient)
	require.Equal(t, bidTrace.GasLimit, convertedBidTrace.GasLimit)
	require.Equal(t, bidTrace.GasUsed, convertedBidTrace.GasUsed)
	require.Equal(t, bidTrace.Value.BigInt().String(), convertedBidTrace.Value.ToBig().String())
}
