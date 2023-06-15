package common

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/attestantio/go-builder-client/api/capella"
	bellatrixspec "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
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
func _HexToAddress(s string) (ret boostTypes.Address) {
	check(ret.UnmarshalText([]byte(s)), " _HexToAddress: ", s)
	return ret
}

// _HexToPubkey converts a hexadecimal string to a BLS Public Key
func _HexToPubkey(s string) (ret boostTypes.PublicKey) {
	check(ret.UnmarshalText([]byte(s)), " _HexToPubkey: ", s)
	return
}

// _HexToSignature converts a hexadecimal string to a BLS Signature
func _HexToSignature(s string) (ret boostTypes.Signature) {
	check(ret.UnmarshalText([]byte(s)), " _HexToSignature: ", s)
	return
}

// _HexToHash converts a hexadecimal string to a Hash
func _HexToHash(s string) (ret boostTypes.Hash) {
	check(ret.FromSlice([]byte(s)), " _HexToHash: ", s)
	return
}

var ValidPayloadRegisterValidator = boostTypes.SignedValidatorRegistration{
	Message: &boostTypes.RegisterValidatorRequestMessage{
		FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
		Timestamp:    1606824043,
		GasLimit:     30000000,
		Pubkey: _HexToPubkey(
			"0x84e975405f8691ad7118527ee9ee4ed2e4e8bae973f6e29aa9ca9ee4aea83605ae3536d22acc9aa1af0545064eacf82e"),
	},
	Signature: _HexToSignature(
		"0xaf12df007a0c78abb5575067e5f8b089cfcc6227e4a91db7dd8cf517fe86fb944ead859f0781277d9b78c672e4a18c5d06368b603374673cf2007966cece9540f3a1b3f6f9e1bf421d779c4e8010368e6aac134649c7a009210780d401a778a5"),
}

func TestBuilderSubmitBlockRequest(sk *bls.SecretKey, bid *BidTraceV2) BuilderSubmitBlockRequest {
	signature, err := boostTypes.SignMessage(bid, boostTypes.DomainBuilder, sk)
	check(err, " SignMessage: ", bid, sk)
	return BuilderSubmitBlockRequest{ //nolint:exhaustruct
		Capella: &capella.SubmitBlockRequest{
			Message:   &bid.BidTrace,
			Signature: [96]byte(signature),
			ExecutionPayload: &consensuscapella.ExecutionPayload{ //nolint:exhaustruct
				Transactions: []bellatrixspec.Transaction{[]byte{0x03}},
				Timestamp:    bid.Slot * 12, // 12 seconds per slot.
				PrevRandao:   _HexToHash("01234567890123456789012345678901"),
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

func TestBuilderSubmitBlockRequestV2(sk *bls.SecretKey, bid *BidTraceV2) *SubmitBlockRequest {
	signature, err := boostTypes.SignMessage(bid, boostTypes.DomainBuilder, sk)
	check(err, " SignMessage: ", bid, sk)

	wRoot, err := hex.DecodeString("792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535")
	check(err)
	return &SubmitBlockRequest{
		Message: &bid.BidTrace,
		ExecutionPayloadHeader: &consensuscapella.ExecutionPayloadHeader{ //nolint:exhaustruct
			TransactionsRoot: [32]byte{},
			Timestamp:        bid.Slot * 12, // 12 seconds per slot.
			PrevRandao:       _HexToHash("01234567890123456789012345678901"),
			WithdrawalsRoot:  phase0.Root(wRoot),
			ExtraData: []byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
		},
		Signature:    [96]byte(signature),
		Transactions: []bellatrixspec.Transaction{[]byte{0x03}},
		Withdrawals:  []*consensuscapella.Withdrawal{},
	}
}
