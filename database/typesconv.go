package database

import (
	"encoding/json"
	"errors"

	"github.com/attestantio/go-builder-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

var ErrUnsupportedExecutionPayload = errors.New("unsupported execution payload version")

func PayloadToExecPayloadEntry(payload *common.BuilderSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	var _payload []byte
	var version string
	var err error
	if payload.Bellatrix != nil {
		_payload, err = json.Marshal(payload.Bellatrix.ExecutionPayload)
		if err != nil {
			return nil, err
		}
		version = common.ForkVersionStringBellatrix
	}
	if payload.Capella != nil {
		_payload, err = json.Marshal(payload.Capella.ExecutionPayload)
		if err != nil {
			return nil, err
		}
		version = common.ForkVersionStringCapella
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
		Timestamp:            timestamp.Unix(),
		TimestampMs:          timestamp.UnixMilli(),
		OptimisticSubmission: payload.OptimisticSubmission,
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

func ExecutionPayloadEntryToExecutionPayload(executionPayloadEntry *ExecutionPayloadEntry) (payload *common.VersionedExecutionPayload, err error) {
	payloadVersion := executionPayloadEntry.Version
	if payloadVersion == common.ForkVersionStringDeneb {
		return nil, ErrUnsupportedExecutionPayload
	} else if payloadVersion == common.ForkVersionStringCapella {
		executionPayload := new(capella.ExecutionPayload)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		capella := api.VersionedExecutionPayload{
			Version:   consensusspec.DataVersionCapella,
			Capella:   executionPayload,
			Bellatrix: nil,
		}
		return &common.VersionedExecutionPayload{
			Capella:   &capella,
			Bellatrix: nil,
		}, nil
	} else if payloadVersion == common.ForkVersionStringBellatrix {
		executionPayload := new(types.ExecutionPayload)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		bellatrix := types.GetPayloadResponse{
			Version: types.VersionString(common.ForkVersionStringBellatrix),
			Data:    executionPayload,
		}
		return &common.VersionedExecutionPayload{
			Bellatrix: &bellatrix,
			Capella:   nil,
		}, nil
	} else {
		return nil, ErrUnsupportedExecutionPayload
	}
}
