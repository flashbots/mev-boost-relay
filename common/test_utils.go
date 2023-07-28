package common

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"

	"github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestLog is used to log information in the test methods
var TestLog = logrus.WithField("testing", true)

func check(err error, args ...interface{}) {
	if err != nil {
		TestLog.Error(err, args)
		panic(err)
	}
}

// _HexToAddress converts a hexadecimal string to an Ethereum address
func _HexToAddress(s string) (ret bellatrix.ExecutionAddress) {
	ret, err := utils.HexToAddress(s)
	check(err, " _HexToAddress: ", s)
	return ret
}

// _HexToPubkey converts a hexadecimal string to a BLS Public Key
func _HexToPubkey(s string) (ret phase0.BLSPubKey) {
	ret, err := utils.HexToPubkey(s)
	check(err, " _HexToPubkey: ", s)
	return ret
}

// _HexToSignature converts a hexadecimal string to a BLS Signature
func _HexToSignature(s string) (ret phase0.BLSSignature) {
	ret, err := utils.HexToSignature(s)
	check(err, " _HexToSignature: ", s)
	return ret
}

// _HexToHash converts a hexadecimal string to a Hash
func _HexToHash(s string) (ret phase0.Hash32) {
	ret, err := utils.HexToHash(s)
	check(err, " _HexToHash: ", s)
	return ret
}

var ValidPayloadRegisterValidator = apiv1.SignedValidatorRegistration{
	Message: &apiv1.ValidatorRegistration{
		FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
		Timestamp:    time.Unix(1606824043, 0),
		GasLimit:     30000000,
		Pubkey: _HexToPubkey(
			"0x84e975405f8691ad7118527ee9ee4ed2e4e8bae973f6e29aa9ca9ee4aea83605ae3536d22acc9aa1af0545064eacf82e"),
	},
	Signature: _HexToSignature(
		"0xaf12df007a0c78abb5575067e5f8b089cfcc6227e4a91db7dd8cf517fe86fb944ead859f0781277d9b78c672e4a18c5d06368b603374673cf2007966cece9540f3a1b3f6f9e1bf421d779c4e8010368e6aac134649c7a009210780d401a778a5"),
}

func TestBuilderSubmitBlockRequest(sk *bls.SecretKey, bid *BidTraceV2) spec.VersionedSubmitBlockRequest {
	signature, err := ssz.SignMessage(bid, ssz.DomainBuilder, sk)
	check(err, " SignMessage: ", bid, sk)
	return spec.VersionedSubmitBlockRequest{ //nolint:exhaustruct
		Version: consensusspec.DataVersionCapella,
		Capella: &capella.SubmitBlockRequest{
			Message:   &bid.BidTrace,
			Signature: [96]byte(signature),
			ExecutionPayload: &consensuscapella.ExecutionPayload{ //nolint:exhaustruct
				Transactions: []bellatrix.Transaction{[]byte{0x03}},
				Timestamp:    bid.Slot * 12, // 12 seconds per slot.
				PrevRandao:   _HexToHash("0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"),
				Withdrawals:  []*consensuscapella.Withdrawal{},
			},
		},
	}
}

func LoadGzippedBytes(t *testing.T, filename string) []byte {
	t.Helper()
	fi, err := os.Open(filename)
	require.NoError(t, err)
	defer fi.Close()
	fz, err := gzip.NewReader(fi)
	require.NoError(t, err)
	defer fz.Close()
	val, err := io.ReadAll(fz)
	require.NoError(t, err)
	return val
}

func LoadGzippedJSON(t *testing.T, filename string, dst any) {
	t.Helper()
	b := LoadGzippedBytes(t, filename)
	err := json.Unmarshal(b, dst)
	require.NoError(t, err)
}

func MustB64Gunzip(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	gzreader, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		panic(err)
	}
	output, err := io.ReadAll(gzreader)
	if err != nil {
		panic(err)
	}
	return output
}
