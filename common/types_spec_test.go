package common

import (
	"bytes"
	"encoding/json"
	"testing"

	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

func TestSubmitBuilderBlockJSON(t *testing.T) {
	jsonBytes := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli.json.gz")

	submitBlockData := new(VersionedSubmitBlockRequest)
	err := json.Unmarshal(jsonBytes, &submitBlockData)
	require.NoError(t, err)

	marshalledJSONBytes, err := json.Marshal(submitBlockData)
	require.NoError(t, err)
	buffer := new(bytes.Buffer)
	err = json.Compact(buffer, jsonBytes)
	require.NoError(t, err)
	expectedJSONBytes := buffer.Bytes()

	require.Equal(t, expectedJSONBytes, bytes.ToLower(marshalledJSONBytes))
}

func TestSignedBeaconBlockJSON(t *testing.T) {
	jsonBytes := LoadGzippedBytes(t, "../testdata/signedBeaconBlock_Goerli.json.gz")
	buffer := new(bytes.Buffer)
	err := json.Compact(buffer, jsonBytes)
	require.NoError(t, err)
	expectedJSONBytes := buffer.Bytes()

	blockRequest := new(VersionedSignedBlockRequest)
	err = json.Unmarshal(jsonBytes, blockRequest)
	require.NoError(t, err)

	marshalledJSONBytes, err := json.Marshal(blockRequest)
	require.NoError(t, err)

	require.Equal(t, expectedJSONBytes, bytes.ToLower(marshalledJSONBytes))
}

func TestSignedBlindedBlockJSON(t *testing.T) {
	jsonBytes := LoadGzippedBytes(t, "../testdata/signedBlindedBeaconBlock_Goerli.json.gz")
	buffer := new(bytes.Buffer)
	err := json.Compact(buffer, jsonBytes)
	require.NoError(t, err)
	expectedJSONBytes := buffer.Bytes()

	blockRequest := new(VersionedSignedBlindedBlockRequest)
	err = json.Unmarshal(jsonBytes, blockRequest)
	require.NoError(t, err)

	marshalledJSONBytes, err := json.Marshal(blockRequest)
	require.NoError(t, err)

	require.Equal(t, expectedJSONBytes, bytes.ToLower(marshalledJSONBytes))
}

func TestBuildGetPayloadResponse(t *testing.T) {
	t.Run("Capella", func(t *testing.T) {
		jsonBytes := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli.json.gz")

		submitBlockData := new(VersionedSubmitBlockRequest)
		err := json.Unmarshal(jsonBytes, &submitBlockData)
		require.NoError(t, err)

		resp, err := BuildGetPayloadResponse(submitBlockData)
		require.NoError(t, err)

		require.Equal(t, spec.DataVersionCapella, resp.Version)
		require.Equal(t, "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121", resp.Capella.BlockHash.String())
	})

	t.Run("Deneb", func(t *testing.T) {
		// TODO: (deneb) add block request from goerli / devnet
		submitBlockData := &VersionedSubmitBlockRequest{
			VersionedSubmitBlockRequest: builderSpec.VersionedSubmitBlockRequest{
				Version: spec.DataVersionDeneb,
				Deneb: &builderApiDeneb.SubmitBlockRequest{
					ExecutionPayload: &deneb.ExecutionPayload{
						BaseFeePerGas: uint256.NewInt(123),
						BlockHash:     phase0.Hash32{0x09},
						Transactions:  []bellatrix.Transaction{},
					},
					BlobsBundle: &builderApiDeneb.BlobsBundle{},
					Message:     &builderApiV1.BidTrace{},
				},
			},
		}

		resp, err := BuildGetPayloadResponse(submitBlockData)
		require.NoError(t, err)

		require.Equal(t, spec.DataVersionDeneb, resp.Version)
		require.Equal(t, "0x0900000000000000000000000000000000000000000000000000000000000000", resp.Deneb.ExecutionPayload.BlockHash.String())
	})
}
