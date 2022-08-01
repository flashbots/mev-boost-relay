package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/types"
)

func VerifyBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest) error {
	if payload.Message.BlockHash != payload.ExecutionPayload.BlockHash {
		return errors.New("blockHash mismatch")
	}

	if payload.Message.ParentHash != payload.ExecutionPayload.ParentHash {
		return errors.New("parentHash mismatch")
	}

	if payload.Message.ProposerFeeRecipient != payload.ExecutionPayload.FeeRecipient {
		return errors.New("feeRecipient mismatch")
	}

	return nil
}
