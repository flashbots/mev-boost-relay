package cmd

import (
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(knownValidatorUpdateCmd)
	knownValidatorUpdateCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	knownValidatorUpdateCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")

	knownValidatorUpdateCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	knownValidatorUpdateCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	knownValidatorUpdateCmd.Flags().BoolVar(&useNetworkKiln, "kiln", false, "Kiln network")
	knownValidatorUpdateCmd.Flags().BoolVar(&useNetworkRopsten, "ropsten", false, "Ropsten network")
	knownValidatorUpdateCmd.Flags().BoolVar(&useNetworkSepolia, "sepolia", false, "Sepolia network")
	knownValidatorUpdateCmd.Flags().BoolVar(&useNetworkGoerliSF5, "goerli-sf5", false, "Goerli Shadow Fork 5")
	knownValidatorUpdateCmd.MarkFlagsMutuallyExclusive("kiln", "ropsten", "sepolia", "goerli-sf5")

	knownValidatorUpdateCmd.Flags().SortFlags = false
}

var knownValidatorUpdateCmd = &cobra.Command{
	Use:   "known-validator-update",
	Short: "Update the known validators in Redis",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/known-validator-update")
		log.Infof("boost-relay %s", Version)

		var networkInfo *common.EthNetworkDetails
		if useNetworkKiln {
			networkInfo, err = common.NewEthNetworkDetails(common.EthNetworkKiln)
		} else if useNetworkRopsten {
			networkInfo, err = common.NewEthNetworkDetails(common.EthNetworkRopsten)
		} else if useNetworkSepolia {
			networkInfo, err = common.NewEthNetworkDetails(common.EthNetworkSepolia)
		} else if useNetworkGoerliSF5 {
			networkInfo, err = common.NewEthNetworkDetails(common.EthNetworkGoerliShadowFork5)
		} else {
			log.Fatal("Please specify a network (eg. --kiln or --ropsten or --sepolia or --goerli-sf5 flags)")
		}
		if err != nil {
			log.WithError(err).Fatalf("unknown network")
		}

		// Connect beacon client to node
		if beaconNodeURI == "" {
			log.Fatal("beacon-uri is required")
		}
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)

		// Check beacon node status
		_, err = beaconClient.SyncStatus()
		if err != nil {
			log.WithError(err).Fatal("error checking beacon-node sync status")
		}

		// Connect to Redis
		if redisURI == "" {
			log.Fatal("redis-uri is required")
		}
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}
		log.Infof("Connected to Redis at %s", redisURI)

		// Query beacon node for known validators
		log.Info("Querying validators from beacon node... (this may take a while)")
		validators, err := beaconClient.FetchValidators()
		if err != nil {
			log.WithError(err).Fatal("failed to fetch validators from beacon node")
		}
		log.Infof("Got %d validators from BN", len(validators))

		// Update Redis with validators
		log.Info("Writing to Redis...")

		// redis.SetKnownValidators(validators)
		var last beaconclient.ValidatorResponseEntry
		for _, v := range validators {
			last = v
			err = redis.SetKnownValidator(types.PubkeyHex(v.Validator.Pubkey), v.Index)
			if err != nil {
				log.WithError(err).WithField("pubkey", v.Validator.Pubkey).Fatal("failed to set known validator in Redis")
			}
		}
		log.Info("Updated Redis ", last.Index, " ", last.Validator.Pubkey)
	},
}
