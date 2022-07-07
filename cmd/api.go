package cmd

import (
	"os"

	"github.com/flashbots/boost-relay/api"
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	// defaults
	defaultListenAddr         = "localhost:9062"
	defaultBeaconURI          = common.GetEnv("BEACON_URI", "")
	defaultredisURI           = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON            = os.Getenv("LOG_JSON") != ""
	defaultLogLevel           = common.GetEnv("LOG_LEVEL", "info")
	defaultGenesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")

	listenAddr    string
	beaconNodeURI string
	redisURI      string
	logJSON       bool
	logLevel      string

	useGenesisForkVersionMainnet bool
	useGenesisForkVersionKiln    bool
	useGenesisForkVersionRopsten bool
	useGenesisForkVersionSepolia bool
	useCustomGenesisForkVersion  string

	apiProposer bool
	apiBuilder  bool

	// // apis and services to start
	// apiProposer = flag.Bool("api-proposer", false, "start proposer API")
	// apiBuilder  = flag.Bool("api-builder", false, "start builder API")
)

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().StringVar(&listenAddr, "listen-addr", defaultListenAddr, "listen address for webserver")
	apiCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	apiCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	apiCmd.Flags().BoolVar(&apiProposer, "api-proposer", false, "start proposer API")
	apiCmd.Flags().BoolVar(&apiBuilder, "api-builder", false, "start builder API")

	apiCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	apiCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	apiCmd.Flags().BoolVar(&useGenesisForkVersionMainnet, "mainnet", false, "use Mainnet genesis fork version 0x00000000 (for signature validation)")
	apiCmd.Flags().BoolVar(&useGenesisForkVersionKiln, "kiln", false, "use Kiln genesis fork version 0x70000069 (for signature validation)")
	apiCmd.Flags().BoolVar(&useGenesisForkVersionRopsten, "ropsten", false, "use Ropsten genesis fork version 0x80000069 (for signature validation)")
	apiCmd.Flags().BoolVar(&useGenesisForkVersionSepolia, "sepolia", false, "use Sepolia genesis fork version 0x90000069 (for signature validation)")
	apiCmd.Flags().StringVar(&useCustomGenesisForkVersion, "genesis-fork-version", defaultGenesisForkVersion, "use a custom genesis fork version (for signature validation)")
	apiCmd.MarkFlagsMutuallyExclusive("mainnet", "kiln", "ropsten", "sepolia", "genesis-fork-version")

	apiCmd.Flags().SortFlags = false
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/api")
		log.Infof("boost-relay %s", version)

		// Set genesis fork version
		genesisForkVersionHex := ""
		if useCustomGenesisForkVersion != "" {
			genesisForkVersionHex = useCustomGenesisForkVersion
		} else if useGenesisForkVersionMainnet {
			genesisForkVersionHex = common.GenesisForkVersionMainnet
		} else if useGenesisForkVersionKiln {
			genesisForkVersionHex = common.GenesisForkVersionKiln
		} else if useGenesisForkVersionRopsten {
			genesisForkVersionHex = common.GenesisForkVersionRopsten
		} else if useGenesisForkVersionSepolia {
			genesisForkVersionHex = common.GenesisForkVersionSepolia
		} else {
			log.Fatal("Please specify a genesis fork version (eg. -mainnet or -kiln or -ropsten or -genesis-fork-version flags)")
		}
		log.Infof("Using genesis fork version: %s", genesisForkVersionHex)

		// Connect beacon client to node
		var beaconClient beaconclient.BeaconNodeClient
		if beaconNodeURI != "" {
			log.Infof("Using beacon endpoint: %s", beaconNodeURI)
			beaconClient = beaconclient.NewProdBeaconClient(log, beaconNodeURI)

			// Check beacon node status
			_, err := beaconClient.SyncStatus()
			if err != nil {
				log.WithError(err).Fatal("Beacon node is syncing")
			}
		}

		// Connect to Redis
		var ds datastore.ProposerDatastore
		if redisURI != "" {
			ds, err = datastore.NewProdProposerDatastore(redisURI)
			if err != nil {
				log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
			}
			log.Infof("Connected to Redis at %s", redisURI)
		}

		opts := api.RelayAPIOpts{
			Log:                   log,
			ListenAddr:            listenAddr,
			BeaconClient:          beaconClient,
			Datastore:             ds,
			GenesisForkVersionHex: genesisForkVersionHex,
			ProposerAPI:           apiProposer,
			BuilderAPI:            apiBuilder,
		}

		// Create the relay service
		srv, err := api.NewRelayAPI(opts)
		if err != nil {
			log.WithError(err).Fatal("failed to create service")
		}

		// Start the server
		log.Println("Webserver listening on", listenAddr)
		log.Fatal(srv.StartServer())
	},
}
