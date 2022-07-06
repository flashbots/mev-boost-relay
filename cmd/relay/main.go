package main

import (
	"context"
	"flag"
	"os"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/server"
	"github.com/sirupsen/logrus"
)

const (
	genesisForkVersionMainnet = "0x00000000"
	genesisForkVersionKiln    = "0x70000069"
	genesisForkVersionRopsten = "0x80000069"
	genesisForkVersionSepolia = "0x90000069"
)

var (
	version = "dev" // is set during build process

	// defaults
	defaultListenAddr         = "localhost:9062"
	defaultBeaconURI          = common.GetEnv("BEACON_URI", "")
	defaultredisURI           = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON            = os.Getenv("LOG_JSON") != ""
	defaultLogLevel           = common.GetEnv("LOG_LEVEL", "info")
	defaultGenesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")

	// cli flags
	listenAddr    = flag.String("listen-addr", defaultListenAddr, "listen address")
	beaconNodeURI = flag.String("beacon-endpoint", defaultBeaconURI, "beacon endpoint")
	redisURI      = flag.String("redis", defaultredisURI, "Redis URI")
	logJSON       = flag.Bool("json", defaultLogJSON, "log in JSON format instead of text")
	logLevel      = flag.String("loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	// network helper flags
	useGenesisForkVersionMainnet = flag.Bool("mainnet", false, "use Mainnet genesis fork version 0x00000000 (for signature validation)")
	useGenesisForkVersionKiln    = flag.Bool("kiln", false, "use Kiln genesis fork version 0x70000069 (for signature validation)")
	useGenesisForkVersionRopsten = flag.Bool("ropsten", false, "use Ropsten genesis fork version 0x80000069 (for signature validation)")
	useGenesisForkVersionSepolia = flag.Bool("sepolia", false, "use Sepolia genesis fork version 0x90000069 (for signature validation)")
	useCustomGenesisForkVersion  = flag.String("genesis-fork-version", defaultGenesisForkVersion, "use a custom genesis fork version (for signature validation)")

	// apis and services to start
	apiProposer = flag.Bool("api-proposer", false, "start proposer API")
	apiBuilder  = flag.Bool("api-builder", false, "start builder API")
)

func main() {
	var err error
	flag.Parse()

	common.LogSetup(*logJSON, *logLevel)
	log := logrus.WithField("module", "cmd/relay")
	log.Infof("boost-relay %s", version)

	// Set genesis fork version
	genesisForkVersionHex := ""
	if *useCustomGenesisForkVersion != "" {
		genesisForkVersionHex = *useCustomGenesisForkVersion
	} else if *useGenesisForkVersionMainnet {
		genesisForkVersionHex = genesisForkVersionMainnet
	} else if *useGenesisForkVersionKiln {
		genesisForkVersionHex = genesisForkVersionKiln
	} else if *useGenesisForkVersionRopsten {
		genesisForkVersionHex = genesisForkVersionRopsten
	} else if *useGenesisForkVersionSepolia {
		genesisForkVersionHex = genesisForkVersionSepolia
	} else {
		log.Fatal("Please specify a genesis fork version (eg. -mainnet or -kiln or -ropsten or -genesis-fork-version flags)")
	}
	log.Infof("Using genesis fork version: %s", genesisForkVersionHex)

	// Create beacon client
	var beaconClient beaconclient.BeaconNodeClient
	if *beaconNodeURI != "" {
		log.Infof("Using beacon endpoint: %s", *beaconNodeURI)
		beaconClient = beaconclient.NewProdBeaconClient(log, *beaconNodeURI)

		// Check beacon node status
		_, err := beaconClient.SyncStatus()
		if err != nil {
			log.WithError(err).Fatal("Beacon node is syncing")
		}
	}

	// Connect to Redis
	var ds datastore.ProposerDatastore
	if *redisURI != "" {
		ds, err = datastore.NewProdProposerDatastore(*redisURI)
		if err != nil {
			log.Fatalf("Failed to connect to Redis at %s", *redisURI)
		}
		log.Infof("Connected to Redis at %s", *redisURI)
	}

	opts := server.RelayServiceOpts{
		Ctx:                   context.Background(),
		Log:                   log,
		ListenAddr:            *listenAddr,
		BeaconClient:          beaconClient,
		Datastore:             ds,
		GenesisForkVersionHex: genesisForkVersionHex,
		ProposerAPI:           *apiProposer,
		BuilderAPI:            *apiBuilder,
	}

	// Create the relay service
	srv, err := server.NewRelayService(opts)
	if err != nil {
		log.WithError(err).Fatal("failed to create service")
	}

	// Start the server
	log.Println("Webserver listening on", *listenAddr)
	log.Fatal(srv.StartServer())
}
