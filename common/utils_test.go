package common

import (
	"context"
	"net/http"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/stretchr/testify/require"
)

func TestMakePostRequest(t *testing.T) {
	// Test errors
	var x chan bool
	resp, err := makeRequest(context.Background(), *http.DefaultClient, http.MethodGet, "", x)
	require.Error(t, err)
	require.Nil(t, resp)

	// To satisfy the bodyclose linter.
	if resp != nil {
		resp.Body.Close()
	}
}

func TestGetMevBoostVersionFromUserAgent(t *testing.T) {
	tests := []struct {
		ua      string
		version string
	}{
		{ua: "", version: "-"},
		{ua: "mev-boost", version: "-"},
		{ua: "mev-boost/v1.0.0", version: "v1.0.0"},
		{ua: "mev-boost/v1.0.0 ", version: "v1.0.0"},
		{ua: "mev-boost/v1.0.0 test", version: "v1.0.0"},
	}

	for _, test := range tests {
		t.Run(test.ua, func(t *testing.T) {
			require.Equal(t, test.version, GetMevBoostVersionFromUserAgent(test.ua))
		})
	}
}

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
