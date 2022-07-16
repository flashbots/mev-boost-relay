package cmd

import (
	"fmt"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	createBlsKeypair bool
)

func init() {
	rootCmd.AddCommand(utilCmd)
	utilCmd.Flags().BoolVar(&createBlsKeypair, "create-bls-keys", false, "create BLS keypair")
}

var utilCmd = &cobra.Command{
	Use: "util",
	Run: func(cmd *cobra.Command, args []string) {
		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/util")

		if createBlsKeypair {
			sk, _, err := bls.GenerateNewKeypair()
			if err != nil {
				log.Fatal(err.Error())
			}

			pubkey := types.BlsPublicKeyToPublicKey(bls.PublicKeyFromSecretKey(sk))

			fmt.Printf("secret key: 0x%x\n", sk.Serialize())
			fmt.Printf("public key: %s\n", pubkey.String())
		}

		// log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		// beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)
		// r, err := beaconClient.GetProposerDuties(26382)
		// if err != nil {
		// 	log.WithError(err).Fatal("error getting proposer duties")
		// }

		// fmt.Printf("%+v\n", r)
	},
}
