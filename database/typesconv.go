package database

import (
	"encoding/json"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

func PayloadToExecPayloadEntry(payload *types.BuilderSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	_payload, err := json.Marshal(payload.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	return &ExecutionPayloadEntry{
		Slot:           payload.Message.Slot,
		ProposerPubkey: payload.Message.ProposerPubkey.String(),
		BlockHash:      payload.ExecutionPayload.BlockHash.String(),

		Version: "bellatrix",
		Payload: string(_payload),
	}, nil
}

func DeliveredPayloadEntryToBidTraceJSON(payload *DeliveredPayloadEntry) common.BidTraceJSON {
	return common.BidTraceJSON{
		Slot:                 payload.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        payload.BuilderPubkey,
		ProposerPubkey:       payload.ProposerPubkey,
		ProposerFeeRecipient: payload.ProposerFeeRecipient,
		GasLimit:             payload.GasLimit,
		GasUsed:              payload.GasUsed,
		Value:                payload.Value,
	}
}

func BuilderSubmissionEntryToBidTraceWithTimestampJSON(payload *BuilderBlockSubmissionEntry) common.BidTraceWithTimestampJSON {
	return common.BidTraceWithTimestampJSON{
		Timestamp: payload.InsertedAt.Unix(),
		BidTraceJSON: common.BidTraceJSON{
			Slot:                 payload.Slot,
			ParentHash:           payload.ParentHash,
			BlockHash:            payload.BlockHash,
			BuilderPubkey:        payload.BuilderPubkey,
			ProposerPubkey:       payload.ProposerPubkey,
			ProposerFeeRecipient: payload.ProposerFeeRecipient,
			GasLimit:             payload.GasLimit,
			GasUsed:              payload.GasUsed,
			Value:                payload.Value,
		},
	}
}
