package database

import (
	"encoding/json"
	"errors"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/deneb"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
)

var ErrUnsupportedExecutionPayload = errors.New("unsupported execution payload version")

func PayloadToExecPayloadEntry(payload *common.VersionedSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	var _payload []byte
	var version string
	var err error

	switch payload.Version {
	case consensusspec.DataVersionCapella:
		_payload, err = json.Marshal(payload.Capella.ExecutionPayload)
		if err != nil {
			return nil, err
		}
		version = common.ForkVersionStringCapella
	case consensusspec.DataVersionDeneb:
		_payload, err = json.Marshal(deneb.ExecutionPayloadAndBlobsBundle{
			ExecutionPayload: payload.Deneb.ExecutionPayload,
			BlobsBundle:      payload.Deneb.BlobsBundle,
		})
		if err != nil {
			return nil, err
		}
		version = common.ForkVersionStringDeneb
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix:
		return nil, ErrUnsupportedExecutionPayload
	}

	submission, err := common.GetBlockSubmissionInfo(payload)
	if err != nil {
		return nil, err
	}

	return &ExecutionPayloadEntry{
		Slot:           submission.Slot,
		ProposerPubkey: submission.Proposer.String(),
		BlockHash:      submission.BlockHash.String(),

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

func ExecutionPayloadEntryToExecutionPayload(executionPayloadEntry *ExecutionPayloadEntry) (payload *api.VersionedSubmitBlindedBlockResponse, err error) {
	payloadVersion := executionPayloadEntry.Version
	if payloadVersion == common.ForkVersionStringDeneb {
		executionPayload := new(deneb.ExecutionPayloadAndBlobsBundle)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		return &api.VersionedSubmitBlindedBlockResponse{
			Version: consensusspec.DataVersionDeneb,
			Deneb:   executionPayload,
		}, nil
	} else if payloadVersion == common.ForkVersionStringCapella {
		executionPayload := new(capella.ExecutionPayload)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		return &api.VersionedSubmitBlindedBlockResponse{
			Version: consensusspec.DataVersionCapella,
			Capella: executionPayload,
		}, nil
	} else {
		return nil, ErrUnsupportedExecutionPayload
	}
}
