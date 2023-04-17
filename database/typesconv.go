package database

import (
	"encoding/json"

	"github.com/flashbots/mev-boost-relay/common"
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

func DeliveredPayloadEntryToBidTraceV2JSON(payload *DeliveredPayloadEntry) common.BidTraceV2JSON {
	return common.BidTraceV2JSON{
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

func BuilderSubmissionEntryToBidTraceV2WithTimestampJSON(payload *BuilderBlockSubmissionEntry) common.BidTraceV2WithTimestampJSON {
	timestamp := payload.InsertedAt
	if payload.ReceivedAt.Valid {
		timestamp = payload.ReceivedAt.Time
	}

	return common.BidTraceV2WithTimestampJSON{
		Timestamp:   timestamp.Unix(),
		TimestampMs: timestamp.UnixMilli(),
		BidTraceV2JSON: common.BidTraceV2JSON{
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

func DeliveredPayloadEntryToBidTraceV3JSON(payload *DeliveredPayloadEntry) common.BidTraceV3JSON {
	bidTrace := common.BidTraceV3JSON{
		Slot:                  payload.Slot,
		ParentHash:            payload.ParentHash,
		BlockHash:             payload.BlockHash,
		BuilderPubkey:         payload.BuilderPubkey,
		ProposerPubkey:        payload.ProposerPubkey,
		ProposerFeeRecipient:  payload.ProposerFeeRecipient,
		GasLimit:              payload.GasLimit,
		GasUsed:               payload.GasUsed,
		Value:                 payload.Value,
		NumTx:                 payload.NumTx,
		BlockNumber:           payload.BlockNumber,
		Timestamp:             int64(0),
		TimestampMs:           int64(0),
		SignedAtTimestampMs:   int64(0),
		EligibleAtTimestampMs: int64(0),
	}

	if payload.SignedAt.Valid {
		bidTrace.SignedAtTimestampMs = payload.SignedAt.Time.UnixMilli()
	}

	return bidTrace
}

func BuilderSubmissionEntryToBidTraceV3JSON(payload *BuilderBlockSubmissionEntry) common.BidTraceV3JSON {
	timestamp := payload.InsertedAt
	if payload.ReceivedAt.Valid {
		timestamp = payload.ReceivedAt.Time
	}

	bidtrace := common.BidTraceV3JSON{
		Timestamp:             timestamp.Unix(),
		TimestampMs:           timestamp.UnixMilli(),
		Slot:                  payload.Slot,
		ParentHash:            payload.ParentHash,
		BlockHash:             payload.BlockHash,
		BuilderPubkey:         payload.BuilderPubkey,
		ProposerPubkey:        payload.ProposerPubkey,
		ProposerFeeRecipient:  payload.ProposerFeeRecipient,
		GasLimit:              payload.GasLimit,
		GasUsed:               payload.GasUsed,
		Value:                 payload.Value,
		NumTx:                 payload.NumTx,
		BlockNumber:           payload.BlockNumber,
		EligibleAtTimestampMs: int64(0),
		SignedAtTimestampMs:   int64(0),
	}

	if payload.EligibleAt.Valid {
		bidtrace.EligibleAtTimestampMs = payload.EligibleAt.Time.UnixMilli()
	}

	return bidtrace
}
