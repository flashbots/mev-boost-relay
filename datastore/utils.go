package datastore

import (
	"math/big"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

func MakeBlockBuilderStatus(isHighPrio, isBlacklisted bool) BlockBuilderStatus {
	if isBlacklisted {
		return RedisBlockBuilderStatusBlacklisted
	} else if isHighPrio {
		return RedisBlockBuilderStatusHighPrio
	} else {
		return RedisBlockBuilderStatusLowPrio
	}
}

func BuildEmptyBellatrixGetHeaderResponse(value uint64) *common.GetHeaderResponse {
	return &common.GetHeaderResponse{ //nolint:exhaustruct
		Bellatrix: &types.GetHeaderResponse{
			Version: "bellatrix",
			Data: &types.SignedBuilderBid{
				Message: &types.BuilderBid{
					Header: &types.ExecutionPayloadHeader{}, //nolint:exhaustruct
					Value:  types.IntToU256(value),
					Pubkey: types.PublicKey{0x01},
				},
				Signature: types.Signature{0x01},
			},
		},
	}
}

// BuilderBids supports redis.SaveBidAndUpdateTopBid
type BuilderBids struct {
	bidValues map[string]*big.Int
}

func NewBuilderBids(bidValueMap map[string]string) *BuilderBids {
	b := BuilderBids{
		bidValues: make(map[string]*big.Int),
	}
	for builderPubkey, bidValue := range bidValueMap {
		b.bidValues[builderPubkey] = new(big.Int)
		b.bidValues[builderPubkey].SetString(bidValue, 10)
	}
	return &b
}

func (b *BuilderBids) getTopBid() (string, *big.Int) {
	topBidBuilderPubkey := ""
	topBidValue := big.NewInt(0)
	for builderPubkey, bidValue := range b.bidValues {
		if bidValue.Cmp(topBidValue) > 0 {
			topBidValue = bidValue
			topBidBuilderPubkey = builderPubkey
		}
	}
	return topBidBuilderPubkey, topBidValue
}

func (b *BuilderBids) builderValue(builderPubkey string) *big.Int {
	val := b.bidValues[builderPubkey]
	if val == nil {
		return big.NewInt(0)
	}
	return val
}
