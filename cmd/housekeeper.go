package cmd

import (
	"os"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/services/housekeeper"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(housekeeperCmd)
	housekeeperCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	housekeeperCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	housekeeperCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	housekeeperCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	housekeeperCmd.Flags().StringVar(&postgresDSN, "db", os.Getenv("POSTGRES_DSN"), "PostgreSQL DSN")

	housekeeperCmd.Flags().StringVar(&network, "network", "", "Which network to use")
	_ = housekeeperCmd.MarkFlagRequired("network")
}

var housekeeperCmd = &cobra.Command{
	Use:   "housekeeper",
	Short: "Service that runs in the background and does various housekeeping (removing old bids, updating proposer duties, saving metrics, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/metrics-saver")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon client and ensure it's synced
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)

		// Connect to Redis and setup the datastore
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		log.Infof("Connecting to Postgres database...")
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database")
		}

		ds, err := datastore.NewDatastore(log, redis, db)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s", postgresDSN)
		}

		opts := &housekeeper.HousekeeperOpts{
			Log:          log,
			Redis:        redis,
			Datastore:    ds,
			BeaconClient: beaconClient,
		}
		service := housekeeper.NewHousekeeper(opts)
		log.Info("Starting service...")
		err = service.Start()
		log.WithError(err).Fatalf("Failed to start housekeeper")
	},
}
