package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	builderApiCapella "github.com/attestantio/go-builder-client/api/capella"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	builderSpec "github.com/attestantio/go-builder-client/spec"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

func TestSSZBuilderSubmission(t *testing.T) {
	testCases := []struct {
		name         string
		filepath     string
		hashTreeRoot string
	}{
		{
			name:         "Capella",
			filepath:     "../testdata/submitBlockPayloadCapella_Goerli",
			hashTreeRoot: "0x014c218ba41c2ed5388e7f0ed055e109b83692c772de5c2800140a95a4b66d13",
		},
		{
			name:         "Deneb",
			filepath:     "../testdata/submitBlockPayloadDeneb_Goerli",
			hashTreeRoot: "0x258007ab62465df2b5d798571d3ba0554302b7569eb1ca99405485d32723d63f",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// json matches marshalled SSZ
			jsonBytes := LoadGzippedBytes(t, fmt.Sprintf("%s.json.gz", testCase.filepath))

			submitBlockData := new(VersionedSubmitBlockRequest)
			err := json.Unmarshal(jsonBytes, &submitBlockData)
			require.NoError(t, err)

			require.False(t, submitBlockData.IsEmpty())
			marshalledSszBytes, err := submitBlockData.MarshalSSZ()
			require.NoError(t, err)

			sszBytes := LoadGzippedBytes(t, fmt.Sprintf("%s.ssz.gz", testCase.filepath))
			require.Equal(t, sszBytes, marshalledSszBytes)

			htr, err := submitBlockData.HashTreeRoot()
			require.NoError(t, err)
			require.Equal(t, testCase.hashTreeRoot, hexutil.Encode(htr[:]))

			// marshalled json matches ssz
			submitBlockSSZ := new(VersionedSubmitBlockRequest)
			err = submitBlockSSZ.UnmarshalSSZ(sszBytes)
			require.NoError(t, err)
			marshalledJSONBytes, err := json.Marshal(submitBlockSSZ)
			require.NoError(t, err)
			// trim white space from expected json
			buffer := new(bytes.Buffer)
			err = json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			require.Equal(t, buffer.Bytes(), marshalledJSONBytes)
		})
	}
}

func TestSSZGetHeaderResponse(t *testing.T) {
	testCases := []struct {
		name         string
		filepath     string
		hashTreeRoot string
	}{
		{
			name:         "Capella",
			filepath:     "../testdata/getHeaderResponseCapella_Mainnet",
			hashTreeRoot: "0x74bfedcdd2da65b4fb14800340ce1abbb202a0dee73aed80b1cf18fb5bc88190",
		},
		{
			name:         "Deneb",
			filepath:     "../testdata/getHeaderResponseDeneb_Goerli",
			hashTreeRoot: "0xc55312d9740709036d0f95168d53576a8c578fbab9cf66f147f8aaf1d2ea74da",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// json -> marshalled ssz -> matches expected ssz
			payload := new(builderSpec.VersionedSignedBuilderBid)

			jsonBytes, err := os.ReadFile(fmt.Sprintf("%s.json", testCase.filepath))
			require.NoError(t, err)

			err = json.Unmarshal(jsonBytes, &payload)
			require.NoError(t, err)

			var ssz []byte
			switch payload.Version { //nolint:exhaustive
			case spec.DataVersionCapella:
				ssz, err = payload.Capella.MarshalSSZ()
				require.NoError(t, err)
			case spec.DataVersionDeneb:
				ssz, err = payload.Deneb.MarshalSSZ()
				require.NoError(t, err)
			default:
				require.Fail(t, "unknown version")
			}

			sszExpectedBytes, err := os.ReadFile(fmt.Sprintf("%s.ssz", testCase.filepath))
			require.NoError(t, err)
			require.Equal(t, sszExpectedBytes, ssz)

			// check hash tree root
			var htr [32]byte
			switch payload.Version { //nolint:exhaustive
			case spec.DataVersionCapella:
				htr, err = payload.Capella.HashTreeRoot()
				require.NoError(t, err)
			case spec.DataVersionDeneb:
				htr, err = payload.Deneb.HashTreeRoot()
				require.NoError(t, err)
			default:
				require.Fail(t, "unknown version")
			}
			require.NoError(t, err)
			require.Equal(t, testCase.hashTreeRoot, hexutil.Encode(htr[:]))

			// ssz -> marshalled json -> matches expected json
			switch payload.Version { //nolint:exhaustive
			case spec.DataVersionCapella:
				payload.Capella = new(builderApiCapella.SignedBuilderBid)
				err = payload.Capella.UnmarshalSSZ(sszExpectedBytes)
				require.NoError(t, err)
			case spec.DataVersionDeneb:
				payload.Deneb = new(builderApiDeneb.SignedBuilderBid)
				err = payload.Deneb.UnmarshalSSZ(sszExpectedBytes)
				require.NoError(t, err)
			default:
				require.Fail(t, "unknown version")
			}
			marshalledJSONBytes, err := json.Marshal(payload)
			require.NoError(t, err)
			// trim white space from expected json
			buffer := new(bytes.Buffer)
			err = json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			require.Equal(t, buffer.Bytes(), marshalledJSONBytes)
		})
	}
}

func BenchmarkDecoding(b *testing.B) {
	jsonBytes, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.json")
	require.NoError(b, err)

	sszBytes, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.ssz")
	require.NoError(b, err)

	payload := new(builderSpec.VersionedSignedBuilderBid)
	b.Run("capella json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = json.Unmarshal(jsonBytes, &payload)
			require.NoError(b, err)
		}
	})
	payload.Capella = new(builderApiCapella.SignedBuilderBid)
	b.Run("capella ssz", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = payload.Capella.UnmarshalSSZ(sszBytes)
			require.NoError(b, err)
		}
	})

	jsonBytes, err = os.ReadFile("../testdata/getHeaderResponseDeneb_Goerli.json")
	require.NoError(b, err)

	sszBytes, err = os.ReadFile("../testdata/getHeaderResponseDeneb_Goerli.ssz")
	require.NoError(b, err)
	payload = new(builderSpec.VersionedSignedBuilderBid)
	b.Run("deneb json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = json.Unmarshal(jsonBytes, &payload)
			require.NoError(b, err)
		}
	})
	payload.Deneb = new(builderApiDeneb.SignedBuilderBid)
	b.Run("deneb ssz", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = payload.Deneb.UnmarshalSSZ(sszBytes)
			require.NoError(b, err)
		}
	})
}
