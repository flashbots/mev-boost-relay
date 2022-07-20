package cmd

import (
	"os"

	"github.com/flashbots/boost-relay/common"
)

var (
	defaultBeaconURI = common.GetEnv("BEACON_URI", "http://localhost:3500")
	defaultredisURI  = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON   = os.Getenv("LOG_JSON") != ""
	defaultLogLevel  = common.GetEnv("LOG_LEVEL", "info")

	beaconNodeURI string
	redisURI      string
	logJSON       bool
	logLevel      string

	useNetworkKiln      bool
	useNetworkRopsten   bool
	useNetworkSepolia   bool
	useNetworkGoerliSF5 bool
)
