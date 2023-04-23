package cmd

import (
	"os"

	"github.com/flashbots/mev-boost-relay/common"
)

var (
	defaultNetwork          = common.GetEnv("NETWORK", "")
	defaultBeaconURIs       = common.GetSliceEnv("BEACON_URIS", []string{"http://localhost:3500"})
	defaultRedisURI         = common.GetEnv("REDIS_URI", "localhost:6379")
	defaultRedisReadonlyURI = common.GetEnv("REDIS_READONLY_URI", "")
	defaultPostgresDSN      = common.GetEnv("POSTGRES_DSN", "")
	defaultMemcachedURIs    = common.GetSliceEnv("MEMCACHED_URIS", nil)
	defaultLogJSON          = os.Getenv("LOG_JSON") != ""
	defaultLogLevel         = common.GetEnv("LOG_LEVEL", "info")

	beaconNodeURIs   []string
	redisURI         string
	redisReadonlyURI string
	postgresDSN      string
	memcachedURIs    []string

	logJSON  bool
	logLevel string

	network string
)
