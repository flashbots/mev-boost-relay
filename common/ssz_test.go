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
	depositData := new(capella.SubmitBlockRequest)

	byteValue, err := os.ReadFile("../testdata/submitBlockPayloadCapella_Goerli.json")
	require.NoError(t, err)

	err = json.Unmarshal(byteValue, &depositData)
	require.NoError(t, err)

	ssz, err := depositData.MarshalSSZ()
	require.NoError(t, err)

	sszExpectedBytes, err := os.ReadFile("../testdata/submitBlockPayloadCapella_Goerli.ssz")
	require.NoError(t, err)
	require.Equal(t, string(sszExpectedBytes), hexutil.Encode(ssz))

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
	require.Equal(t, string(sszExpectedBytes), hexutil.Encode(ssz))

	htr, err := payload.Capella.HashTreeRoot()
	require.NoError(t, err)
	require.Equal(t, "0x74bfedcdd2da65b4fb14800340ce1abbb202a0dee73aed80b1cf18fb5bc88190", hexutil.Encode(htr[:]))
}
