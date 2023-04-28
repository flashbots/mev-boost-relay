package main

//
// Script to create a signed validator registration
//

import (
	"fmt"

	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	gasLimit     = 30000000
	feeRecipient = "0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"
	timestamp    = 1606824043
)

func Perr(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	mainnetDetails, err := common.NewEthNetworkDetails(common.EthNetworkMainnet)
	Perr(err)

	sk, pubkey, err := bls.GenerateNewKeypair()
	Perr(err)

	pk, err := boostTypes.BlsPublicKeyToPublicKey(pubkey)
	Perr(err)

	// Fill in validator registration details
	validatorRegistration := boostTypes.RegisterValidatorRequestMessage{ //nolint:exhaustruct
		GasLimit:  uint64(gasLimit),
		Timestamp: uint64(timestamp),
	}

	validatorRegistration.Pubkey, err = boostTypes.HexToPubkey(pk.String())
	Perr(err)
	validatorRegistration.FeeRecipient, err = boostTypes.HexToAddress(feeRecipient)
	Perr(err)

	sig, err := boostTypes.SignMessage(&validatorRegistration, mainnetDetails.DomainBuilder, sk)
	Perr(err)
	fmt.Println("privkey:", sk.String())
	fmt.Println("pubkey: ", pk.String())
	fmt.Println("sig:    ", sig.String())
}
