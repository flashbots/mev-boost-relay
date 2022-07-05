package main

import (
	"flag"
	"os"

	"github.com/flashbots/boost-relay/common"
	"github.com/sirupsen/logrus"
)

var (
	version = "dev" // is set during build process

	// defaults
	defaultBeaconURI = common.GetEnv("BEACON_URI", "http://localhost:3500")
	defaultredisURI  = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON   = os.Getenv("LOG_JSON") != ""
	defaultLogLevel  = common.GetEnv("LOG_LEVEL", "info")

	// cli flags
	redisUpdateValidators = flag.Bool("redis-update-validators", false, "Update redis with all current validators known by the BN")
	beaconNodeURI         = flag.String("beacon-endpoint", defaultBeaconURI, "beacon endpoint")
	redisURI              = flag.String("redis", defaultredisURI, "Redis URI")
	logJSON               = flag.Bool("json", defaultLogJSON, "log in JSON format instead of text")
	logLevel              = flag.String("loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")
)

func main() {
	flag.Parse()

	// signingDomain, _ := common.ComputeDomain(types.DomainTypeAppBuilder, "0x00000000", types.Root{}.String())
	// fmt.Println("xxx", signingDomain)

	common.LogSetup(*logJSON, *logLevel)
	logrus.Infof("boost-relay util %s", version)

	if *redisUpdateValidators {
		taskRedisUpdateValidators(*redisURI, *beaconNodeURI)
	} else {
		logrus.Warn("No task specified")
	}
}

func taskRedisUpdateValidators(redisURI, beaconURI string) {
	log := logrus.WithField("task", "redisUpdateValidators")
	log.Info("updating redis with validators...")

	redis, err := common.NewRedisService(redisURI)
	if err == nil {
		log.Infof("Connected to redis at %s", redisURI)
	} else {
		log.WithError(err).Fatal("failed to create redis service")
	}

	// Connect to Beacon Node, and fetch all validators
	if beaconURI == "" {
		log.Fatal("Please specify a beacon endpoint (using the -beacon-endpoint flag)")
	}
	log.Infof("Using beacon endpoint: %s", beaconURI)
	beaconClient := common.NewBeaconClientService(beaconURI)

	log.Info("Querying validators from beacon node... (this may take a while)")
	validators, err := beaconClient.FetchValidators()
	if err != nil {
		log.WithError(err).Fatal("failed to fetch validators from beacon node")
	}
	log.Infof("Got %d validators from BN", len(validators))

	// Update redis with validators
	log.Info("Writing to Redis...")
	for _, v := range validators {
		redis.SetKnownValidator(v.Validator.Pubkey)
	}
	log.Info("Updated Redis")
}
