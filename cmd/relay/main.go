package main

import (
	"flag"
	"os"

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
	defaultListenAddr = "localhost:9062"
	// defaultBeaconEndpoint     = "http://localhost:5052"
	defaultGenesisForkVersion = os.Getenv("GENESIS_FORK_VERSION")
	defaultLogJSON            = os.Getenv("LOG_JSON") != ""
	defaultLogLevel           = getEnv("LOG_LEVEL", "info")

	// cli flags
	listenAddr = flag.String("listen-addr", defaultListenAddr, "listen address")
	// beaconEndpoint = flag.String("beacon-endpoint", defaultBeaconEndpoint, "beacon endpoint")
	logJSON  = flag.Bool("json", defaultLogJSON, "log in JSON formate instead of text")
	logLevel = flag.String("loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	useGenesisForkVersionMainnet = flag.Bool("mainnet", false, "use Mainnet genesis fork version 0x00000000 (for signature validation)")
	useGenesisForkVersionKiln    = flag.Bool("kiln", false, "use Kiln genesis fork version 0x70000069 (for signature validation)")
	useGenesisForkVersionRopsten = flag.Bool("ropsten", false, "use Ropsten genesis fork version 0x80000069 (for signature validation)")
	useGenesisForkVersionSepolia = flag.Bool("sepolia", false, "use Sepolia genesis fork version 0x90000069 (for signature validation)")
	useCustomGenesisForkVersion  = flag.String("genesis-fork-version", defaultGenesisForkVersion, "use a custom genesis fork version (for signature validation)")
)

var log = logrus.WithField("module", "cmd/relay")

func main() {
	flag.Parse()
	logrus.SetOutput(os.Stdout)

	if *logJSON {
		log.Logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		log.Logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
		})

	}

	if *logLevel != "" {
		lvl, err := logrus.ParseLevel(*logLevel)
		if err != nil {
			log.Fatalf("Invalid loglevel: %s", *logLevel)
		}
		logrus.SetLevel(lvl)
	}

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

	// validatorService := server.NewBeaconClientValidatorService(*beaconEndpoint)
	// // TODO: should be done at the start of every epoch
	// err := validatorService.FetchValidators()
	// if err != nil {
	// 	log.WithError(err).Fatal("failed to fetch validators from beacon node")
	// }

	srv, err := server.NewRelayService(*listenAddr, nil, log, genesisForkVersionHex)
	if err != nil {
		log.WithError(err).Fatal("failed to create service")
	}

	log.Println("listening on", *listenAddr)
	log.Fatal(srv.StartHTTPServer())
}

func getEnv(key string, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}
