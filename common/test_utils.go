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
		Timestamp:    1234356,
		GasLimit:     278234191203,
		Pubkey: _HexToPubkey(
			"0x8a1d7b8dd64e0aafe7ea7b6c95065c9364cf99d38470c12ee807d55f7de1529ad29ce2c422e0b65e3d5a05c02caca249"),
	},
	// Signed by 0x4e343a647c5a5c44d76c2c58b63f02cdf3a9a0ec40f102ebc26363b4b1b95033
	Signature: _HexToSignature(
		"0x8209b5391cd69f392b1f02dbc03bab61f574bb6bb54bf87b59e2a85bdc0756f7db6a71ce1b41b727a1f46ccc77b213bf0df1426177b5b29926b39956114421eaa36ec4602969f6f6370a44de44a6bce6dae2136e5fb594cce2a476354264d1ea"),
}
