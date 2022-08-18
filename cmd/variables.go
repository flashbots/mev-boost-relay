package cmd

import (
	"os"

	"github.com/flashbots/mev-boost-relay/common"
)

var (
	defaultBeaconURIs = common.GetSliceEnv("BEACON_URI", []string{"http://localhost:3500"})
	defaultredisURI   = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultLogJSON    = os.Getenv("LOG_JSON") != ""
	defaultLogLevel   = common.GetEnv("LOG_LEVEL", "info")

	beaconNodeURIs []string
	redisURI       string
	postgresDSN    string

	logJSON  bool
	logLevel string

	network string
)
