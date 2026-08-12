package database

import (
	"testing"
	"time"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/stretchr/testify/require"
)

func TestExecutionPayloadEntryToExecutionPayload(t *testing.T) {
	filename := "../testdata/executionPayloadCapella_Goerli.json.gz"
	payloadBytes := common.LoadGzippedBytes(t, filename)
	entry := &ExecutionPayloadEntry{
		ID:         123,
		Slot:       5552306,
		InsertedAt: time.Unix(1685616301, 0),

		ProposerPubkey: "0x8559727ee65c295279332198029c939557f4d2aba0751fc55f71d0733b8aa17cd0301232a7f21a895f81eacf55c97ec4",
		BlockHash:      "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121",
		Version:        common.ForkVersionStringCapella,
		Payload:        string(payloadBytes),
	}

	payload, err := ExecutionPayloadEntryToExecutionPayload(entry)
	require.NoError(t, err)
	require.Equal(t, "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121", payload.Capella.BlockHash.String())
}

func TestExecutionPayloadEntryToExecutionPayloadDeneb(t *testing.T) {
	filename := "../testdata/executionPayloadAndBlobsBundleDeneb_Goerli.json.gz"
	payloadBytes := common.LoadGzippedBytes(t, filename)
	entry := &ExecutionPayloadEntry{
		ID:         123,
		Slot:       7432891,
		InsertedAt: time.Unix(1685616301, 0),

		ProposerPubkey: "0x8559727ee65c295279332198029c939557f4d2aba0751fc55f71d0733b8aa17cd0301232a7f21a895f81eacf55c97ec4",
		BlockHash:      "0xbd1ae4f7edb2315d2df70a8d9881fab8d6763fb1c00533ae729050928c38d05a",
		Version:        common.ForkVersionStringDeneb,
		Payload:        string(payloadBytes),
	}

	payload, err := ExecutionPayloadEntryToExecutionPayload(entry)
	require.NoError(t, err)
	require.Equal(t, "0xbd1ae4f7edb2315d2df70a8d9881fab8d6763fb1c00533ae729050928c38d05a", payload.Deneb.ExecutionPayload.BlockHash.String())
	require.Len(t, payload.Deneb.BlobsBundle.Blobs, 1)
}

func TestExecutionPayloadEntryToExecutionPayloadElectra(t *testing.T) {
	filename := "../testdata/executionPayloadAndBlobsBundleElectra_Goerli.json.gz"
	payloadBytes := common.LoadGzippedBytes(t, filename)
	entry := &ExecutionPayloadEntry{
		ID:         123,
		Slot:       6,
		InsertedAt: time.Unix(1685616301, 0),

		ProposerPubkey: "0x8419cf00f2783c430dc861a710984d0429d3b3a7f6db849b4f5c05e0d87339704c5c7f5eede6adfc8776d666587b5932",
		BlockHash:      "0x8bc5ee08e27659360187285be156c31daa8e37513a5df7e006322e1268f6b4e1",
		Version:        common.ForkVersionStringElectra,
		Payload:        string(payloadBytes),
	}

	payload, err := ExecutionPayloadEntryToExecutionPayload(entry)
	require.NoError(t, err)
	require.Equal(t, "0x8bc5ee08e27659360187285be156c31daa8e37513a5df7e006322e1268f6b4e1", payload.Electra.ExecutionPayload.BlockHash.String())
	require.Len(t, payload.Electra.BlobsBundle.Blobs, 1)
}
