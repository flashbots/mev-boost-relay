package cmd

import (
	"fmt"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(testCmd)
}

var testCmd = &cobra.Command{
	Use: "test",
	Run: func(cmd *cobra.Command, args []string) {
		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/test")
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)
		r, err := beaconClient.GetProposerDuties(26382)
		if err != nil {
			log.WithError(err).Fatal("error getting proposer duties")
		}

		fmt.Printf("%+v\n", r)
	},
}
