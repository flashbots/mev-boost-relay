package cmd

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/services/api"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	apiDefaultListenAddr = "localhost:9062"
	apiDefaultBlockSim   = "http://localhost:8545"
)

var (
	apiListenAddr   string
	apiPprofEnabled bool
	apiSecretKey    string
	apiBlockSimURL  string
)

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	apiCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	apiCmd.Flags().StringVar(&apiListenAddr, "listen-addr", apiDefaultListenAddr, "listen address for webserver")
	apiCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	apiCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	apiCmd.Flags().StringVar(&postgresDSN, "db", "", "PostgreSQL DSN")
	apiCmd.Flags().StringVar(&apiSecretKey, "secret-key", "", "secret key for signing bids")
	apiCmd.Flags().BoolVar(&apiPprofEnabled, "pprof", false, "enable pprof API")
	apiCmd.Flags().StringVar(&apiBlockSimURL, "blocksim", apiDefaultBlockSim, "URL for block simulator")

	apiCmd.Flags().StringVar(&network, "network", "", "Which network to use")
	_ = apiCmd.MarkFlagRequired("network")
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/api")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon client and ensure it's synced
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)

		// Connect to Redis
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}
		log.Infof("Connected to Redis at %s", redisURI)

		// Connect to Postgres
		log.Infof("Connecting to Postgres database...")
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s", postgresDSN)
		}

		ds, err := datastore.NewDatastore(log, redis, db)
		if err != nil {
			log.WithError(err).Fatalf("Failed setting up prod datastore")
		}

		// Decode the private key
		envSkBytes, err := hexutil.Decode(apiSecretKey)
		if err != nil {
			log.WithError(err).Fatal("incorrect secret key provided")
		}
		sk, err := bls.SecretKeyFromBytes(envSkBytes[:])
		if err != nil {
			log.WithError(err).Fatal("incorrect builder API secret key provided")
		}

		opts := api.RelayAPIOpts{
			Log:           log,
			ListenAddr:    apiListenAddr,
			BeaconClient:  beaconClient,
			Datastore:     ds,
			Redis:         redis,
			DB:            db,
			EthNetDetails: *networkInfo,
			PprofAPI:      apiPprofEnabled,
			SecretKey:     sk,
			BlockSimURL:   apiBlockSimURL,
		}

		// Create the relay service
		srv, err := api.NewRelayAPI(opts)
		if err != nil {
			log.WithError(err).Fatal("failed to create service")
		}

		// Start the server
		log.Infof("Webserver starting on %s ...", apiListenAddr)
		log.Fatal(srv.StartServer())
	},
}
