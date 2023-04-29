package common

import (
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
)

// TestLog is used to log information in the test methods
var TestLog = logrus.WithField("testing", true)

// _HexToAddress converts a hexadecimal string to an Ethereum address
func _HexToAddress(s string) (ret types.Address) {
	err := ret.UnmarshalText([]byte(s))
	if err != nil {
		TestLog.Error(err, " _HexToAddress: ", s)
		panic(err)
	}
	return ret
}

// _HexToPubkey converts a hexadecimal string to a BLS Public Key
func _HexToPubkey(s string) (ret types.PublicKey) {
	err := ret.UnmarshalText([]byte(s))
	if err != nil {
		TestLog.Error(err, " _HexToPubkey: ", s)
		panic(err)
	}
	return
}

// _HexToSignature converts a hexadecimal string to a BLS Signature
func _HexToSignature(s string) (ret types.Signature) {
	err := ret.UnmarshalText([]byte(s))
	if err != nil {
		TestLog.Error(err, " _HexToSignature: ", s)
		panic(err)
	}
	return
}

var ValidPayloadRegisterValidator = types.SignedValidatorRegistration{
	Message: &types.RegisterValidatorRequestMessage{
		FeeRecipient: _HexToAddress("0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"),
		Timestamp:    1606824043,
		GasLimit:     30000000,
		Pubkey: _HexToPubkey(
			"0x84e975405f8691ad7118527ee9ee4ed2e4e8bae973f6e29aa9ca9ee4aea83605ae3536d22acc9aa1af0545064eacf82e"),
	},
	Signature: _HexToSignature(
		"0xaf12df007a0c78abb5575067e5f8b089cfcc6227e4a91db7dd8cf517fe86fb944ead859f0781277d9b78c672e4a18c5d06368b603374673cf2007966cece9540f3a1b3f6f9e1bf421d779c4e8010368e6aac134649c7a009210780d401a778a5"),
}
