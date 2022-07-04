package main

import (
	"flag"
	"os"

	"github.com/flashbots/boost-relay/common"
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
	defaultBeaconEndpoint     = "http://localhost:3500"
	defaultredisURI           = getEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON            = os.Getenv("LOG_JSON") != ""
	defaultLogLevel           = getEnv("LOG_LEVEL", "info")
	defaultGenesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")

	// cli flags
	listenAddr     = flag.String("listen-addr", defaultListenAddr, "listen address")
	beaconEndpoint = flag.String("beacon-endpoint", defaultBeaconEndpoint, "beacon endpoint")
	logJSON        = flag.Bool("json", defaultLogJSON, "log in JSON format instead of text")
	logLevel       = flag.String("loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")
	redisURI       = flag.String("redis", defaultredisURI, "Redis URI")

	// network helper flags
	useGenesisForkVersionMainnet = flag.Bool("mainnet", false, "use Mainnet genesis fork version 0x00000000 (for signature validation)")
	useGenesisForkVersionKiln    = flag.Bool("kiln", false, "use Kiln genesis fork version 0x70000069 (for signature validation)")
	useGenesisForkVersionRopsten = flag.Bool("ropsten", false, "use Ropsten genesis fork version 0x80000069 (for signature validation)")
	useGenesisForkVersionSepolia = flag.Bool("sepolia", false, "use Sepolia genesis fork version 0x90000069 (for signature validation)")
	useCustomGenesisForkVersion  = flag.String("genesis-fork-version", defaultGenesisForkVersion, "use a custom genesis fork version (for signature validation)")
)

func main() {
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

	// Connect to Redis
	cache, err := server.NewRedisService(*redisURI)
	if err == nil {
		log.Infof("Connected to redis at %s", *redisURI)
	} else {
		log.WithError(err).Fatal("failed to create redis service")
	}

	// Connect to Beacon Node, and fetch all validators
	if *beaconEndpoint == "" {
		log.Fatal("Please specify a beacon endpoint (using the -beacon-endpoint flag)")
	}
	log.Infof("Using beacon endpoint: %s", *beaconEndpoint)
	validatorService := common.NewBeaconClientService(*beaconEndpoint)

	// Create the relay service
	srv, err := server.NewRelayService(*listenAddr, validatorService, log, genesisForkVersionHex, cache)
	if err != nil {
		log.WithError(err).Fatal("failed to create service")
	}

	// Start the server
	log.Println("Webserver listening on", *listenAddr)
	log.Fatal(srv.StartServer())
}

func getEnv(key string, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}
