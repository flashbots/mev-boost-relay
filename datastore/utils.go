package datastore

import (
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
