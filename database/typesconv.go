package database

import (
	"encoding/json"

	"github.com/flashbots/go-boost-utils/types"
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
