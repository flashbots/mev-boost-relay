package cmd

import (
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/boost-relay/api"
	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	apiDefaultListenAddr = "localhost:9062"
)

var (
	apiListenAddr       string
	apiPprofEnabled     bool
	apiSecretKey        string
	apiGetHeaderDelayMs int64
)

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().StringVar(&apiListenAddr, "listen-addr", apiDefaultListenAddr, "listen address for webserver")
	apiCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	apiCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	apiCmd.Flags().BoolVar(&apiPprofEnabled, "pprof", false, "enable pprof API")
	apiCmd.Flags().Int64Var(&apiGetHeaderDelayMs, "getheader-delay-ms", 0, "ms to wait on getHeader requests")
	apiCmd.Flags().StringVar(&apiSecretKey, "secret-key", "", "secret key for signing bids")

	apiCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	apiCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	apiCmd.Flags().BoolVar(&useNetworkKiln, "kiln", false, "Kiln network")
	apiCmd.Flags().BoolVar(&useNetworkRopsten, "ropsten", false, "Ropsten network")
	apiCmd.Flags().BoolVar(&useNetworkSepolia, "sepolia", false, "Sepolia network")
	apiCmd.Flags().BoolVar(&useNetworkGoerliSF5, "goerli-sf5", false, "Goerli Shadow Fork 5")
	apiCmd.MarkFlagsMutuallyExclusive("kiln", "ropsten", "sepolia", "goerli-sf5")

	apiCmd.Flags().SortFlags = false
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the API server",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/api")
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

		log.Infof("Using network: %s", networkInfo.Name)
		log.Infof("Using genesis validators root: %s", networkInfo.GenesisValidatorsRootHex)
		log.Infof("Using genesis fork version: %s", networkInfo.GenesisForkVersionHex)
		log.Infof("Using bellatrix fork version: %s", networkInfo.BellatrixForkVersionHex)

		// Connect to beacon client and ensure it's synced
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)

		// Connect to Redis and setup the datastore
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}
		log.Infof("Connected to Redis at %s", redisURI)
		ds := datastore.NewProdDatastore(redis)

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
			Log:               log,
			ListenAddr:        apiListenAddr,
			BeaconClient:      beaconClient,
			Datastore:         ds,
			EthNetDetails:     *networkInfo,
			PprofAPI:          apiPprofEnabled,
			GetHeaderWaitTime: time.Duration(apiGetHeaderDelayMs) * time.Millisecond,
			SecretKey:         sk,
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
