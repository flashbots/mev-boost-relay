// Package config defines the default configuration and binds to environment variables
//
// To setup a new config variable:
// 1. Define a default value (config.*Default*): shared by the cmd flag and the env variable
// 2. Define a mapping key (config.Key*): to bind the cmd flag and the env variable
// 3. Blend both using bindAndSet(Mappingkey, ENV, defaultValue)
//
// To setup a new command flag using the values from the config:
//  1. Define a command flag without assigning it to a variable (without the Var())
//  2. Use the default value from the config (config.*Default*)
//  3. Use Viper to bind the command flag to the mapping key (config.Key*)
//     The BindPFlag() should be done in the PreRun stage to workaround: https://github.com/spf13/viper/issues/233
//     Lookup() receives the flag name
//  4. Get and cast the value using the config.Get*
//
// Example:
// Definition of a command with 2 flags where only the first one supports fetching the value from an environment variable
//
// config.go
//
//	const (
//		DefaultFirstFlag = "default value for fist flag"
//		KeyFirstFlag     = "KeyAPIDebug"
//	)
//	bindAndSet(KeyFirstFlag, "FIRST_FLAG", DefaultFirstFlag)
//
// command.go
//
//	var secondFlag uint64
//
//	func init() {
//		rootCmd.AddCommand(Cmd)
//		Cmd.Flags().String("firstFlag", config.DefaultFirstFlag, "first flag")
//		Cmd.Flags().Uint64Var(&secondFlag, "other-flag", 2, "second flag")
//	}
//
//	var Cmd = &cobra.Command{
//		Use: "command",
//		PreRun: func(cmd *cobra.Command, args []string) {
//			_ = viper.BindPFlag(config.KeyFirstFlag, cmd.Flags().Lookup("firstFlag"))
//		},
//		Run: func(cmd *cobra.Command, args []string) {
//			fmt.Println(config.GetString(config.KeyFirstFlag))
//		},
//	}
//
// The command can be run either using a flag or an environment variable:
//
//	$ go run . command
//	default value for fist flag
//
//	$ go run . command --firstFlag "Hello from the flag"
//	Hello from the flag
//
//	$ FIRST_FLAG="Hello from the environment" go run . command
//	Hello from the environment
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
	KeyNetwork        = "KeyNetwork"
	KeyRedisURI       = "KeyRedisURI"
	KeyPostgresDSN    = "KeyPostgresDSN"
	KeyBeaconNodeURIs = "KeyBeaconNodeURIs"
	KeyLogJSON        = "KeyLogJSON"
	KeyLogLevel       = "KeyLogLevel"

	// API cmd
	KeyAPIListenAddr   = "KeyAPIListenAddr"
	KeyAPIBlockSimURL  = "KeyAPIBlockSimURL"
	KeyAPISecretKey    = "KeyAPISecretKey"
	KeyAPILogTag       = "KeyAPILogTag"
	KeyAPILogVersion   = "KeyAPILogVersion"
	KeyAPIPprofEnabled = "KeyAPIPprofEnabled"
	KeyAPIInternalAPI  = "KeyAPIInternalAPI"
	KeyAPIDebug        = "KeyAPIDebug"

	// API services
	KeyBlockSimMaxConcurrent        = "KeyBlockSimMaxConcurrent"
	KeyForceGetHeader204            = "KeyForceGetHeader204"
	KeyDisableBlockPublishing       = "KeyDisableBlockPublishing"
	KeyDisableLowprioBuilders       = "KeyDisableLowprioBuilders"
	KeyNumActiveValidatorProcessors = "KeyNumActiveValidatorProcessors"
	KeyNumValidatorRegProcessors    = "KeyNumValidatorRegProcessors"
	KeyGetpayloadRetryTimeoutMs     = "KeyGetpayloadRetryTimeoutMs"

	// Website
	KeyWebsiteListenAddr        = "KeyWebsiteListenAddr"
	KeyWebsiteShowConfigDetails = "KeyWebsiteShowConfigDetails"
	KeyWebsiteLinkBeaconchain   = "KeyWebsiteLinkBeaconchain"
	KeyWebsiteLinkEtherscan     = "KeyWebsiteLinkEtherscan"
	KeyWebsiteRelayURL          = "KeyWebsiteRelayURL"
	KeyWebsitePubkeyOverride    = "KeyWebsitePubkeyOverride"

	// Database
	KeyDBDontApplySchema = "KeyDBDontApplySchema"
	KeyDBTablePrefix     = "KeyDBTablePrefix"
	KeyDBRunTests        = "KeyDBRunTests"
	KeyDBTestDSN         = "KeyDBTestDSN"

	// Redis
	KeyActiveValidatorHours = "KeyActiveValidatorHours"

	// Beacon
	KeyAllowSyncingBeaconNode = "KeyAllowSyncingBeaconNode"
)

var DefaultBeaconURIs = []string{"http://localhost:3500"}

func init() {
	// Common: Api, HouseKeeper & Website
	bindAndSet(KeyNetwork, "NETWORK", DefaultNetwork)
	bindAndSet(KeyRedisURI, "REDIS_URI", DefaultRedisURI)
	bindAndSet(KeyPostgresDSN, "POSTGRES_DSN", DefaultPostgresDSN)
	bindAndSet(KeyBeaconNodeURIs, "BEACON_URIS", DefaultBeaconURIs)
	bindAndSet(KeyLogJSON, "LOG_JSON", DefaultLogJSON)
	bindAndSet(KeyLogLevel, "LOG_LEVEL", DefaultLogLevel)

	// API cmd
	bindAndSet(KeyAPIListenAddr, "LISTEN_ADDR", APIDefaultListenAddr)
	bindAndSet(KeyAPIBlockSimURL, "BLOCKSIM_URI", APIDefaultBlockSim)
	bindAndSet(KeyAPISecretKey, "SECRET_KEY", APIDefaultSecretKey)
	bindAndSet(KeyAPILogTag, "LOG_TAG", APIDefaultLogTag)
	bindAndSet(KeyAPIPprofEnabled, "PPROF", APIDefaultPprofEnabled)
	bindAndSet(KeyAPIInternalAPI, "ENABLE_INTERNAL_API", APIDefaultInternalAPIEnabled)
	bindAndSet(KeyAPIDebug, "DEBUG_API", APIDefaultDebug)

	// API services
	bindAndSet(KeyBlockSimMaxConcurrent, "BLOCKSIM_MAX_CONCURRENT", 4)
	bindAndSet(KeyForceGetHeader204, "FORCE_GET_HEADER_204", false)
	bindAndSet(KeyDisableBlockPublishing, "DISABLE_BLOCK_PUBLISHING", false)
	bindAndSet(KeyDisableLowprioBuilders, "DISABLE_LOWPRIO_BUILDERS", false)
	bindAndSet(KeyNumActiveValidatorProcessors, "NUM_ACTIVE_VALIDATOR_PROCESSORS", 10)
	bindAndSet(KeyNumValidatorRegProcessors, "NUM_VALIDATOR_REG_PROCESSORS", 10)
	bindAndSet(KeyGetpayloadRetryTimeoutMs, "GETPAYLOAD_RETRY_TIMEOUT_MS", 100)

	// Website
	// FIXME: Website & API share the same environment variable
	bindAndSet(KeyWebsiteListenAddr, "LISTEN_ADDR", WebsiteDefaultListenAddr)
	bindAndSet(KeyWebsiteShowConfigDetails, "SHOW_CONFIG_DETAILS", WebsiteDefaultShowConfigDetails)
	bindAndSet(KeyWebsiteLinkBeaconchain, "LINK_BEACONCHAIN", WebsiteDefaultLinkBeaconchain)
	bindAndSet(KeyWebsiteLinkEtherscan, "LINK_ETHERSCAN", WebsiteDefaultLinkEtherscan)
	bindAndSet(KeyWebsiteRelayURL, "RELAY_URL", WebsiteDefaultRelayURL)
	bindAndSet(KeyWebsitePubkeyOverride, "PUBKEY_OVERRIDE", WebsiteDefaultPubkeyOverride)

	// Database
	bindAndSet(KeyDBDontApplySchema, "DB_DONT_APPLY_SCHEMA", "")
	bindAndSet(KeyDBTablePrefix, "DB_TABLE_PREFIX", "dev")
	bindAndSet(KeyDBRunTests, "RUN_DB_TESTS", false)
	bindAndSet(KeyDBTestDSN, "TEST_DB_DSN", "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable")

	// Redis
	bindAndSet(KeyActiveValidatorHours, "ACTIVE_VALIDATOR_HOURS", 3)

	// Beacon
	bindAndSet(KeyAllowSyncingBeaconNode, "ALLOW_SYNCING_BEACON_NODE", "")
}

// bindAndSet maps the command flag with the env variable through the key
func bindAndSet(key, envVariable string, defaultValue any) {
	log := common.LogSetup(viper.GetBool("logJSON"), viper.GetString("logLevel"))
	if err := viper.BindEnv(key, envVariable); err != nil {
		log.WithError(err).Fatalf("Failed to BindEnv: %s", envVariable)
	}
	viper.SetDefault(key, defaultValue)
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
