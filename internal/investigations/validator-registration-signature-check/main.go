package main

//
// Script to create a signed validator registration
//

import (
	"fmt"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	gasLimit     = 30000000
	feeRecipient = "0xdb65fEd33dc262Fe09D9a2Ba8F80b329BA25f941"
	timestamp    = int64(1606824043)
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

	pk, err := utils.BlsPublicKeyToPublicKey(pubkey)
	Perr(err)

	// Fill in validator registration details
	validatorRegistration := builderApiV1.ValidatorRegistration{ //nolint:exhaustruct
		GasLimit:  uint64(gasLimit),
		Timestamp: time.Unix(timestamp, 0),
	}

	validatorRegistration.Pubkey, err = utils.HexToPubkey(pk.String())
	Perr(err)
	validatorRegistration.FeeRecipient, err = utils.HexToAddress(feeRecipient)
	Perr(err)

	sig, err := ssz.SignMessage(&validatorRegistration, mainnetDetails.DomainBuilder, sk)
	Perr(err)
	fmt.Println("privkey:", sk.String())
	fmt.Println("pubkey: ", pk.String())
	fmt.Println("sig:    ", sig.String())
}
