// Package config defines the default configuration and binds to environment variables
package config

import (
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/spf13/viper"
)

const (
	DefaultNetwork     = ""
	DefaultRedisURI    = "localhost:6379"
	DefaultPostgresDSN = ""
	DefaultLogJSON     = false
	DefaultLogLevel    = "info"

	APIDefaultListenAddr         = "localhost:9062"
	APIDefaultBlockSim           = "http://localhost:8545"
	APIDefaultSecretKey          = ""
	APIDefaultLogTag             = ""
	APIDefaultLogVersion         = false
	APIDefaultPprofEnabled       = false
	APIDefaultInternalAPIEnabled = false
	APIDefaultDebug              = false

	WebsiteDefaultListenAddr        = "localhost:9060"
	WebsiteDefaultShowConfigDetails = false
	WebsiteDefaultLinkBeaconchain   = "https://beaconcha.in"
	WebsiteDefaultLinkEtherscan     = "https://etherscan.io"
	WebsiteDefaultRelayURL          = ""
	WebsiteDefaultPubkeyOverride    = ""
)

var (
	DefaultBeaconURIs = []string{"http://localhost:3500"}

	configEnvs = make(map[string]string)
)

func init() {
	// Common: Api, HouseKeeper & Website
	bindAndSet("network", "NETWORK", DefaultNetwork)
	bindAndSet("redisURI", "REDIS_URI", DefaultRedisURI)
	bindAndSet("postgresDSN", "POSTGRES_DSN", DefaultPostgresDSN)
	bindAndSet("beaconNodeURIs", "BEACON_URIS", DefaultBeaconURIs)
	bindAndSet("logJSON", "LOG_JSON", DefaultLogJSON)
	bindAndSet("logLevel", "LOG_LEVEL", DefaultLogLevel)

	// API cmd
	bindAndSet("apiListenAddr", "LISTEN_ADDR", APIDefaultListenAddr)
	bindAndSet("apiBlockSimURL", "BLOCKSIM_URI", APIDefaultBlockSim)
	bindAndSet("apiSecretKey", "SECRET_KEY", APIDefaultSecretKey)
	bindAndSet("apiLogTag", "LOG_TAG", APIDefaultLogTag)
	bindAndSet("apiPprofEnabled", "PPROF", APIDefaultPprofEnabled)
	bindAndSet("apiInternalAPI", "ENABLE_INTERNAL_API", APIDefaultInternalAPIEnabled)
	bindAndSet("apiDebug", "DEBUG_API", APIDefaultDebug)

	// API services
	bindAndSet("blockSimMaxConcurrent", "BLOCKSIM_MAX_CONCURRENT", 4)
	bindAndSet("forceGetHeader204", "FORCE_GET_HEADER_204", false)
	bindAndSet("disableBlockPublishing", "DISABLE_BLOCK_PUBLISHING", false)
	bindAndSet("disableLowprioBuilders", "DISABLE_LOWPRIO_BUILDERS", false)
	bindAndSet("numActiveValidatorProcessors", "NUM_ACTIVE_VALIDATOR_PROCESSORS", 10)
	bindAndSet("numValidatorRegProcessors", "NUM_VALIDATOR_REG_PROCESSORS", 10)
	bindAndSet("getpayloadRetryTimeoutMs", "GETPAYLOAD_RETRY_TIMEOUT_MS", 100)

	// Website
	// FIXME: Website & API share the same environment variable
	bindAndSet("websitetListenAddr", "LISTEN_ADDR", WebsiteDefaultListenAddr)
	bindAndSet("websiteShowConfigDetails", "SHOW_CONFIG_DETAILS", WebsiteDefaultShowConfigDetails)
	bindAndSet("websiteLinkBeaconchain", "LINK_BEACONCHAIN", WebsiteDefaultLinkBeaconchain)
	bindAndSet("websiteLinkEtherscan", "LINK_ETHERSCAN", WebsiteDefaultLinkEtherscan)
	bindAndSet("websiteRelayURL", "RELAY_URL", WebsiteDefaultRelayURL)
	bindAndSet("websitePubkeyOverride", "PUBKEY_OVERRIDE", WebsiteDefaultPubkeyOverride)

	// Database
	bindAndSet("dbPrintSchema", "PRINT_SCHEMA", false)
	bindAndSet("dbDontApplySchema", "DB_DONT_APPLY_SCHEMA", "")
	bindAndSet("dbTablePrefix", "DB_TABLE_PREFIX", "dev")

	// Redis
	bindAndSet("activeValidatorHours", "ACTIVE_VALIDATOR_HOURS", 3)

	// Beacon
	bindAndSet("allowSyncingBeaconNode", "ALLOW_SYNCING_BEACON_NODE", "")
}

func bindAndSet(key, envVariable string, defaultValue interface{}) {
	log := common.LogSetup(viper.GetBool("logJSON"), viper.GetString("logLevel"))
	if err := viper.BindEnv(key, envVariable); err != nil {
		log.WithError(err).Fatalf("Failed to BindEnv: %s", envVariable)
	}
	viper.SetDefault(key, defaultValue)
	configEnvs[key] = envVariable
}

// GetConfig returns the key/values for the config
func GetConfig() map[string]string {
	config := make(map[string]string)
	for k, v := range configEnvs {
		config[v] = viper.GetString(k)
	}
	// FIXME: Needs to mask or skip sensitive data
	return config
}

// Get returns an interface. For a specific value use one of the Get____ methods.
func Get(key string) interface{} { return viper.Get(key) }

// GetInt returns the value associated with the key as an integer.
func GetInt(key string) int { return viper.GetInt(key) }

// GetInt64 returns the value associated with the key as an integer.
func GetInt64(key string) int64 { return viper.GetInt64(key) }

// GetStringSlice returns the value associated with the key as a slice of strings.
func GetStringSlice(key string) []string { return viper.GetStringSlice(key) }

// GetString returns the value associated with the key as a string.
func GetString(key string) string { return viper.GetString(key) }

// GetBool returns the value associated with the key as a boolean.
func GetBool(key string) bool { return viper.GetBool(key) }
