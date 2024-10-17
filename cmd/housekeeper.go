package cmd

import (
	"net/url"
	"os"
	"strings"

	gethCommon "github.com/ethereum/go-ethereum/common"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/mevcommitclient"
	"github.com/flashbots/mev-boost-relay/services/housekeeper"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	hkDefaultPprofEnabled    = os.Getenv("PPROF") == "1"
	hkDefaultPprofListenAddr = common.GetEnv("PPROF_LISTEN_ADDR", "localhost:9064")

	hkPprofEnabled    bool
	hkPprofListenAddr string
)

func init() {
	rootCmd.AddCommand(housekeeperCmd)
	housekeeperCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	housekeeperCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	housekeeperCmd.Flags().StringSliceVar(&beaconNodeURIs, "beacon-uris", defaultBeaconURIs, "beacon endpoints")
	housekeeperCmd.Flags().StringVar(&redisURI, "redis-uri", defaultRedisURI, "redis uri")
	housekeeperCmd.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")

	housekeeperCmd.Flags().StringVar(&network, "network", defaultNetwork, "Which network to use")

	housekeeperCmd.Flags().BoolVar(&hkPprofEnabled, "pprof", hkDefaultPprofEnabled, "enable pprof API")
	housekeeperCmd.Flags().StringVar(&hkPprofListenAddr, "pprof-listen-addr", hkDefaultPprofListenAddr, "listen address for pprof server")

	housekeeperCmd.Flags().StringVar(&mevCommitRPC, "mev-commit-rpc", defaultMevCommitRPC, "mev-commit-chain RPC endpoint")
	housekeeperCmd.Flags().StringVar(&ethereumL1RPC, "ethereum-l1-rpc", defaultEthereumL1RPC, "Ethereum L1 RPC endpoint")
	housekeeperCmd.Flags().StringVar(&providerRegistryAddr, "provider-registry-addr", defaultProviderRegistryAddr, "mev-commit provider registry contract address")
	housekeeperCmd.Flags().StringVar(&validatorOptInRouterAddr, "validator-optin-router-addr", defaultValidatorOptInRouterAddr, "mev-commit validator opt-in router contract address")
}

var housekeeperCmd = &cobra.Command{
	Use:   "housekeeper",
	Short: "Service that runs in the background and does various housekeeping (removing old bids, updating proposer duties, saving metrics, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		log := common.LogSetup(logJSON, logLevel).WithFields(logrus.Fields{
			"service": "relay/housekeeper",
			"version": Version,
		})
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)
		log.Debug(networkInfo.String())

		// Connect to beacon clients and ensure it's synced
		if len(beaconNodeURIs) == 0 {
			log.Fatalf("no beacon endpoints specified")
		}
		log.Infof("Using beacon endpoints: %s", strings.Join(beaconNodeURIs, ", "))
		var beaconInstances []beaconclient.IBeaconInstance
		for _, uri := range beaconNodeURIs {
			beaconInstances = append(beaconInstances, beaconclient.NewProdBeaconInstance(log, uri, uri))
		}
		beaconClient := beaconclient.NewMultiBeaconClient(log, beaconInstances)

		// Connect to Redis and setup the datastore
		redis, err := datastore.NewRedisCache(networkInfo.Name, redisURI, "")
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		// Connect to Postgres
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		mevCommitClient, err := mevcommitclient.NewMevCommitClient(
			ethereumL1RPC,
			mevCommitRPC,
			gethCommon.HexToAddress(validatorOptInRouterAddr),
			gethCommon.HexToAddress(providerRegistryAddr),
		)
		if err != nil {
			log.WithError(err).Fatal("Failed to create mev-commit client")
		}

		opts := &housekeeper.HousekeeperOpts{
			Log:          log,
			Redis:        redis,
			DB:           db,
			BeaconClient: beaconClient,

			PprofAPI:           hkPprofEnabled,
			PprofListenAddress: hkPprofListenAddr,

			MevCommitClient: mevCommitClient,
		}
		service := housekeeper.NewHousekeeper(opts)
		log.Info("Starting housekeeper service...")
		err = service.Start()
		log.WithError(err).Fatalf("Failed to start housekeeper")
	},
}
