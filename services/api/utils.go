package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/types"
)

var (
	ErrBlockHashMismatch  = errors.New("blockHash mismatch")
	ErrParentHashMismatch = errors.New("parentHash mismatch")
)

func SanityCheckBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest) error {
	if payload.Message.BlockHash != payload.ExecutionPayload.BlockHash {
		return ErrBlockHashMismatch
	}

	if payload.Message.ParentHash != payload.ExecutionPayload.ParentHash {
		return ErrParentHashMismatch
	}

	return nil
}

func checkBLSPublicKeyHex(pkHex string) error {
	var proposerPubkey types.PublicKey
	return proposerPubkey.UnmarshalText([]byte(pkHex))
}
