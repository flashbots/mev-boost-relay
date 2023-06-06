package database

import (
	"os"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

func TestExecutionPayloadEntryToExecutionPayload(t *testing.T) {
	capellaPayload := new(capella.ExecutionPayload)
	val, err := os.ReadFile("../testdata/executionPayloadCapella_Goerli.json")
	require.NoError(t, err)
	err = capellaPayload.UnmarshalJSON(val)
	require.NoError(t, err)

	entry := &ExecutionPayloadEntry{
		ID:         123,
		Slot:       5552306,
		InsertedAt: time.Unix(1685616301, 0),

		ProposerPubkey: "0x8559727ee65c295279332198029c939557f4d2aba0751fc55f71d0733b8aa17cd0301232a7f21a895f81eacf55c97ec4",
		BlockHash:      "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121",
		Version:        common.ForkVersionStringCapella,
		Payload:        string(val),
	}

	payload, err := ExecutionPayloadEntryToExecutionPayload(entry)
	require.NoError(t, err)
	require.Equal(t, capellaPayload.BlockHash.String(), payload.Capella.Capella.BlockHash.String())

	// _, err = OrigConvert(entry)
	// require.Error(t, err)
	// require.Equal(t, "invalid character 'c' looking for beginning of value", err.Error())
}

// func OrigConvert(executionPayloadEntry *ExecutionPayloadEntry) (payload *common.VersionedExecutionPayload, err error) {
// 	var res consensusspec.DataVersion
// 	err = json.Unmarshal([]byte(executionPayloadEntry.Version), &res)
// 	if err != nil {
// 		return nil, err
// 	}
// 	switch res {
// 	case consensusspec.DataVersionCapella:
// 		executionPayload := new(capella.ExecutionPayload)
// 		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
// 		if err != nil {
// 			return nil, err
// 		}
// 		capella := api.VersionedExecutionPayload{
// 			Version:   res,
// 			Capella:   executionPayload,
// 			Bellatrix: nil,
// 		}
// 		return &common.VersionedExecutionPayload{
// 			Capella:   &capella,
// 			Bellatrix: nil,
// 		}, nil
// 	case consensusspec.DataVersionBellatrix:
// 		executionPayload := new(types.ExecutionPayload)
// 		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
// 		if err != nil {
// 			return nil, err
// 		}
// 		bellatrix := types.GetPayloadResponse{
// 			Version: types.VersionString(res.String()),
// 			Data:    executionPayload,
// 		}
// 		return &common.VersionedExecutionPayload{
// 			Bellatrix: &bellatrix,
// 			Capella:   nil,
// 		}, nil
// 	case consensusspec.DataVersionDeneb:
// 		return nil, errors.New("todo")
// 	case consensusspec.DataVersionAltair, consensusspec.DataVersionPhase0:
// 		return nil, errors.New("unsupported execution payload version")
// 	default:
// 		return nil, errors.New("unknown execution payload version")
// 	}
// }
