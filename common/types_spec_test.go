package common

import (
	"bytes"
	"encoding/json"
	"testing"

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
