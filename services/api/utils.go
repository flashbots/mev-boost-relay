package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/types"
)

var (
	ErrBlockHashMismatch    = errors.New("blockHash mismatch")
	ErrParentHashMismatch   = errors.New("parentHash mismatch")
	ErrFeeRecipientMismatch = errors.New("feeRecipient mismatch")
)

func VerifyBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest) error {
	if payload.Message.BlockHash != payload.ExecutionPayload.BlockHash {
		return ErrBlockHashMismatch
	}

	if payload.Message.ParentHash != payload.ExecutionPayload.ParentHash {
		return ErrParentHashMismatch
	}

	if payload.Message.ProposerFeeRecipient != payload.ExecutionPayload.FeeRecipient {
		return ErrFeeRecipientMismatch
	}

	return nil
}
