package common

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
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

	require.Equal(t, expectedJSONBytes, marshalledJSONBytes)
}

func TestSignedBeaconBlockJSON(t *testing.T) {
	testCases := []struct {
		name     string
		filepath string
	}{
		{
			name:     "Capella",
			filepath: "../testdata/signedBeaconBlockCapella_Goerli.json.gz",
		},
		{
			name:     "Deneb",
			filepath: "../testdata/signedBeaconBlockContentsDeneb_Goerli.json.gz",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)
			buffer := new(bytes.Buffer)
			err := json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			expectedJSONBytes := buffer.Bytes()

			blockRequest := new(VersionedSignedProposal)
			err = json.Unmarshal(jsonBytes, blockRequest)
			require.NoError(t, err)

			marshalledJSONBytes, err := json.Marshal(blockRequest)
			require.NoError(t, err)

			require.Equal(t, expectedJSONBytes, marshalledJSONBytes)
		})
	}
}

func TestSignedBlindedBlockJSON(t *testing.T) {
	testCases := []struct {
		name     string
		filepath string
	}{
		{
			name:     "Capella",
			filepath: "../testdata/signedBlindedBeaconBlockCapella_Goerli.json.gz",
		},
		{
			name:     "Deneb",
			filepath: "../testdata/signedBlindedBeaconBlockDeneb_Goerli.json.gz",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)
			buffer := new(bytes.Buffer)
			err := json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			expectedJSONBytes := buffer.Bytes()

			blockRequest := new(VersionedSignedBlindedBeaconBlock)
			err = json.Unmarshal(jsonBytes, blockRequest)
			require.NoError(t, err)

			marshalledJSONBytes, err := json.Marshal(blockRequest)
			require.NoError(t, err)

			require.Equal(t, expectedJSONBytes, marshalledJSONBytes)
		})
	}
}

func TestBuildGetPayloadResponse(t *testing.T) {
	testCases := []struct {
		name      string
		filepath  string
		version   spec.DataVersion
		blockHash string
	}{
		{
			name:      "Capella",
			filepath:  "../testdata/submitBlockPayloadCapella_Goerli.json.gz",
			version:   spec.DataVersionCapella,
			blockHash: "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121",
		},
		{
			name:      "Deneb",
			filepath:  "../testdata/submitBlockPayloadDeneb_Goerli.json.gz",
			version:   spec.DataVersionDeneb,
			blockHash: "0x195e2aac0a52cf26428336142e74eafd55d9228f315c2f2fe9253406ef9ef544",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)

			submitBlockData := new(VersionedSubmitBlockRequest)
			err := json.Unmarshal(jsonBytes, &submitBlockData)
			require.NoError(t, err)

			resp, err := BuildGetPayloadResponse(submitBlockData)
			require.NoError(t, err)

			require.Equal(t, testCase.version, resp.Version)
			blockHash, err := resp.BlockHash()
			require.NoError(t, err)
			require.Equal(t, testCase.blockHash, blockHash.String())
		})
	}
}
