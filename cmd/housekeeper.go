package cmd

import (
	"net/url"
	"strings"

	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/config"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/services/housekeeper"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(housekeeperCmd)

	housekeeperCmd.Flags().String("network", config.DefaultNetwork, "Which network to use")
	housekeeperCmd.Flags().String("redis-uri", config.DefaultRedisURI, "Redis uri")
	housekeeperCmd.Flags().String("db", config.DefaultPostgresDSN, "PostgreSQL DSN")
	housekeeperCmd.Flags().StringSlice("beacon-uris", config.DefaultBeaconURIs, "beacon endpoints")
	housekeeperCmd.Flags().Bool("json", config.DefaultLogJSON, "log in JSON format instead of text")
	housekeeperCmd.Flags().String("logLevel", config.DefaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")
}

var housekeeperCmd = &cobra.Command{
	Use:   "housekeeper",
	Short: "Service that runs in the background and does various housekeeping (removing old bids, updating proposer duties, saving metrics, etc.)",
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("network", cmd.Flags().Lookup("network"))
		_ = viper.BindPFlag("redisURI", cmd.Flags().Lookup("redis-uri"))
		_ = viper.BindPFlag("postgresDSN", cmd.Flags().Lookup("db"))
		_ = viper.BindPFlag("beaconNodeURIs", cmd.Flags().Lookup("beacon-uris"))
		_ = viper.BindPFlag("logJSON", cmd.Flags().Lookup("json"))
		_ = viper.BindPFlag("logLevel", cmd.Flags().Lookup("loglevel"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		log := common.LogSetup(config.GetBool(config.LogJSON), config.GetString(config.LogLevel)).WithField("service", "relay/housekeeper")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(config.GetString(config.Network))
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon clients and ensure it's synced
		beaconNodeURIs := config.GetStringSlice(config.BeaconNodeURIs)
		if len(beaconNodeURIs) == 0 {
			log.Fatalf("no beacon endpoints specified")
		}
		log.Infof("Using beacon endpoints: %s", strings.Join(beaconNodeURIs, ", "))
		var beaconInstances []beaconclient.IBeaconInstance
		for _, uri := range beaconNodeURIs {
			beaconInstances = append(beaconInstances, beaconclient.NewProdBeaconInstance(log, uri))
		}
		beaconClient := beaconclient.NewMultiBeaconClient(log, beaconInstances)

		// Connect to Redis and setup the datastore
		redisURI := config.GetString(config.RedisURI)
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		// Connect to Postgres
		postgresDSN := config.GetString(config.PostgresDSN)
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		opts := &housekeeper.HousekeeperOpts{
			Log:          log,
			Redis:        redis,
			DB:           db,
			BeaconClient: beaconClient,
		}
		service := housekeeper.NewHousekeeper(opts)
		log.Info("Starting housekeeper service...")
		err = service.Start()
		log.WithError(err).Fatalf("Failed to start housekeeper")
	},
}
