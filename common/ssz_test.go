package common

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/spec"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
)

func TestSSZBuilderSubmission(t *testing.T) {
	byteValue := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli.json.gz")

	depositData := new(capella.SubmitBlockRequest)
	err := json.Unmarshal(byteValue, &depositData)
	require.NoError(t, err)

	ssz, err := depositData.MarshalSSZ()
	require.NoError(t, err)

	sszExpectedBytes := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli.ssz.gz")
	require.Equal(t, sszExpectedBytes, ssz)

	htr, err := depositData.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0x014c218ba41c2ed5388e7f0ed055e109b83692c772de5c2800140a95a4b66d13", hexutil.Encode(htr[:]))
}

func TestSSZGetHeaderResponse(t *testing.T) {
	payload := new(spec.VersionedSignedBuilderBid)

	byteValue, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.json")
	require.NoError(t, err)

	err = json.Unmarshal(byteValue, &payload)
	require.NoError(t, err)

	ssz, err := payload.Capella.MarshalSSZ()
	require.NoError(t, err)

	sszExpectedBytes, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.ssz")
	require.NoError(t, err)
	require.Equal(t, sszExpectedBytes, ssz)

	htr, err := payload.Capella.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0x74bfedcdd2da65b4fb14800340ce1abbb202a0dee73aed80b1cf18fb5bc88190", hexutil.Encode(htr[:]))
}

func BenchmarkDecoding(b *testing.B) {
	jsonBytes, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.json")
	require.NoError(b, err)

	sszBytes, err := os.ReadFile("../testdata/getHeaderResponseCapella_Mainnet.ssz")
	require.NoError(b, err)

	payload := new(spec.VersionedSignedBuilderBid)
	b.Run("json", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = json.Unmarshal(jsonBytes, &payload)
			require.NoError(b, err)
		}
	})
	payload.Capella = new(capella.SignedBuilderBid)
	b.Run("ssz", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err = payload.Capella.UnmarshalSSZ(sszBytes)
			require.NoError(b, err)
		}
	})
}
