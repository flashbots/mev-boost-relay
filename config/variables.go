// Package config defines the default configuration and binds to environment variables
package config

import (
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/spf13/viper"
)

const (
	// Default values
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

	// Common: Api, HouseKeeper & Website
	Network        = "Network"
	RedisURI       = "RedisURI"
	PostgresDSN    = "PostgresDSN"
	BeaconNodeURIs = "BeaconNodeURIs"
	LogJSON        = "LogJSON"
	LogLevel       = "LogLevel"

	// API cmd
	APIListenAddr   = "APIListenAddr"
	APIBlockSimURL  = "APIBlockSimURL"
	APISecretKey    = "APISecretKey"
	APILogTag       = "APILogTag"
	APILogVersion   = "APILogVersion"
	APIPprofEnabled = "APIPprofEnabled"
	APIInternalAPI  = "APIInternalAPI"
	APIDebug        = "APIDebug"

	// API services
	BlockSimMaxConcurrent        = "BlockSimMaxConcurrent"
	ForceGetHeader204            = "ForceGetHeader204"
	DisableBlockPublishing       = "DisableBlockPublishing"
	DisableLowprioBuilders       = "DisableLowprioBuilders"
	NumActiveValidatorProcessors = "NumActiveValidatorProcessors"
	NumValidatorRegProcessors    = "NumValidatorRegProcessors"
	GetpayloadRetryTimeoutMs     = "GetpayloadRetryTimeoutMs"

	// Website
	WebsiteListenAddr        = "WebsiteListenAddr"
	WebsiteShowConfigDetails = "WebsiteShowConfigDetails"
	WebsiteLinkBeaconchain   = "WebsiteLinkBeaconchain"
	WebsiteLinkEtherscan     = "WebsiteLinkEtherscan"
	WebsiteRelayURL          = "WebsiteRelayURL"
	WebsitePubkeyOverride    = "WebsitePubkeyOverride"

	// Database
	DBPrintSchema     = "DBPrintSchema"
	DBDontApplySchema = "DBDontApplySchema"
	DBTablePrefix     = "DBTablePrefix"

	// Datastore
	DisableBidMemoryCache = "DisableBidMemoryCache"

	// Redis
	ActiveValidatorHours = "ActiveValidatorHours"

	// Beacon
	AllowSyncingBeaconNode = "AllowSyncingBeaconNode"
)

var (
	DefaultBeaconURIs = []string{"http://localhost:3500"}

	configEnvs = make(map[string]string)
)

func init() {
	// Common: Api, HouseKeeper & Website
	bindAndSet(Network, "NETWORK", DefaultNetwork)
	bindAndSet(RedisURI, "REDIS_URI", DefaultRedisURI)
	bindAndSet(PostgresDSN, "POSTGRES_DSN", DefaultPostgresDSN)
	bindAndSet(BeaconNodeURIs, "BEACON_URIS", DefaultBeaconURIs)
	bindAndSet(LogJSON, "LOG_JSON", DefaultLogJSON)
	bindAndSet(LogLevel, "LOG_LEVEL", DefaultLogLevel)

	// API cmd
	bindAndSet(APIListenAddr, "LISTEN_ADDR", APIDefaultListenAddr)
	bindAndSet(APIBlockSimURL, "BLOCKSIM_URI", APIDefaultBlockSim)
	bindAndSet(APISecretKey, "SECRET_KEY", APIDefaultSecretKey)
	bindAndSet(APILogTag, "LOG_TAG", APIDefaultLogTag)
	bindAndSet(APIPprofEnabled, "PPROF", APIDefaultPprofEnabled)
	bindAndSet(APIInternalAPI, "ENABLE_INTERNAL_API", APIDefaultInternalAPIEnabled)
	bindAndSet(APIDebug, "DEBUG_API", APIDefaultDebug)

	// API services
	bindAndSet(BlockSimMaxConcurrent, "BLOCKSIM_MAX_CONCURRENT", 4)
	bindAndSet(ForceGetHeader204, "FORCE_GET_HEADER_204", false)
	bindAndSet(DisableBlockPublishing, "DISABLE_BLOCK_PUBLISHING", false)
	bindAndSet(DisableLowprioBuilders, "DISABLE_LOWPRIO_BUILDERS", false)
	bindAndSet(NumActiveValidatorProcessors, "NUM_ACTIVE_VALIDATOR_PROCESSORS", 10)
	bindAndSet(NumValidatorRegProcessors, "NUM_VALIDATOR_REG_PROCESSORS", 10)
	bindAndSet(GetpayloadRetryTimeoutMs, "GETPAYLOAD_RETRY_TIMEOUT_MS", 100)

	// Website
	// FIXME: Website & API share the same environment variable
	bindAndSet(WebsiteListenAddr, "LISTEN_ADDR", WebsiteDefaultListenAddr)
	bindAndSet(WebsiteShowConfigDetails, "SHOW_CONFIG_DETAILS", WebsiteDefaultShowConfigDetails)
	bindAndSet(WebsiteLinkBeaconchain, "LINK_BEACONCHAIN", WebsiteDefaultLinkBeaconchain)
	bindAndSet(WebsiteLinkEtherscan, "LINK_ETHERSCAN", WebsiteDefaultLinkEtherscan)
	bindAndSet(WebsiteRelayURL, "RELAY_URL", WebsiteDefaultRelayURL)
	bindAndSet(WebsitePubkeyOverride, "PUBKEY_OVERRIDE", WebsiteDefaultPubkeyOverride)

	// Database
	bindAndSet(DBPrintSchema, "PRINT_SCHEMA", false)
	bindAndSet(DBDontApplySchema, "DB_DONT_APPLY_SCHEMA", "")
	bindAndSet(DBTablePrefix, "DB_TABLE_PREFIX", "dev")

	// Redis
	bindAndSet(ActiveValidatorHours, "ACTIVE_VALIDATOR_HOURS", 3)

	// Beacon
	bindAndSet(AllowSyncingBeaconNode, "ALLOW_SYNCING_BEACON_NODE", "")
}

func bindAndSet(key, envVariable string, defaultValue any) {
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
