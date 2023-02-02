package database

import (
	"encoding/json"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/types"
)

func PayloadToExecPayloadEntry(payload *common.BuilderSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	var _payload []byte
	var version string
	var err error
	if payload.Bellatrix != nil {
		_payload, err = json.Marshal(payload.Bellatrix.ExecutionPayload)
		if err != nil {
			return nil, err
		}
		version = "bellatrix"
	}
	if payload.Capella != nil {
		_payload, err = json.Marshal(payload.Capella.ExecutionPayload)
		if err != nil {
			return nil, err
		}
		version = "capella"
	}
	return &ExecutionPayloadEntry{
		Slot:           payload.Slot(),
		ProposerPubkey: payload.ProposerPubkey(),
		BlockHash:      payload.BlockHash(),

		Version: version,
		Payload: string(_payload),
	}, nil
}

func DeliveredPayloadEntryToBidTraceV2JSON(payload *DeliveredPayloadEntry) types.BidTraceV2JSON {
	return types.BidTraceV2JSON{
		Slot:                 payload.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        payload.BuilderPubkey,
		ProposerPubkey:       payload.ProposerPubkey,
		ProposerFeeRecipient: payload.ProposerFeeRecipient,
		GasLimit:             payload.GasLimit,
		GasUsed:              payload.GasUsed,
		Value:                payload.Value,
		NumTx:                payload.NumTx,
		BlockNumber:          payload.BlockNumber,
	}
}

func BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(payload *BuilderBlockSubmissionEntry) types.BidTraceV2WithTimestampJSON {
	timestamp := payload.InsertedAt
	if payload.ReceivedAt.Valid {
		timestamp = payload.ReceivedAt.Time
	}

	return types.BidTraceV2WithTimestampJSON{
		Timestamp:   timestamp.Unix(),
		TimestampMs: timestamp.UnixMilli(),
		BidTraceV2JSON: types.BidTraceV2JSON{
			Slot:                 payload.Slot,
			ParentHash:           payload.ParentHash,
			BlockHash:            payload.BlockHash,
			BuilderPubkey:        payload.BuilderPubkey,
			ProposerPubkey:       payload.ProposerPubkey,
			ProposerFeeRecipient: payload.ProposerFeeRecipient,
			GasLimit:             payload.GasLimit,
			GasUsed:              payload.GasUsed,
			Value:                payload.Value,
			NumTx:                payload.NumTx,
			BlockNumber:          payload.BlockNumber,
		},
	}
}
