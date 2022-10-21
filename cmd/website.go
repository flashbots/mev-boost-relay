package cmd

import (
	"net/url"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/config"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/services/website"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(websiteCmd)

	websiteCmd.Flags().String("network", config.DefaultNetwork, "Which network to use")
	websiteCmd.Flags().String("redis-uri", config.DefaultRedisURI, "redis uri")
	websiteCmd.Flags().String("db", config.DefaultPostgresDSN, "PostgreSQL DSN")
	websiteCmd.Flags().Bool("json", config.DefaultLogJSON, "log in JSON format instead of text")
	websiteCmd.Flags().String("loglevel", config.DefaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")
	websiteCmd.Flags().String("listen-addr", config.WebsiteDefaultListenAddr, "listen address for webserver")
	websiteCmd.Flags().Bool("show-config-details", config.WebsiteDefaultShowConfigDetails, "show config details")
	websiteCmd.Flags().String("link-beaconchain", config.WebsiteDefaultLinkBeaconchain, "url for beaconcha.in")
	websiteCmd.Flags().String("link-etherscan", config.WebsiteDefaultLinkEtherscan, "url for etherscan")
	websiteCmd.Flags().String("relay-url", config.WebsiteDefaultRelayURL, "full url for the relay (https://pubkey@host)")
	websiteCmd.Flags().String("pubkey-override", config.WebsiteDefaultPubkeyOverride, "override for public key")
}

var websiteCmd = &cobra.Command{
	Use:   "website",
	Short: "Start the website server",
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("network", cmd.Flags().Lookup("network"))
		_ = viper.BindPFlag("redisURI", cmd.Flags().Lookup("redis-uri"))
		_ = viper.BindPFlag("postgresDSN", cmd.Flags().Lookup("db"))
		_ = viper.BindPFlag("logJSON", cmd.Flags().Lookup("json"))
		_ = viper.BindPFlag("logLevel", cmd.Flags().Lookup("loglevel"))
		_ = viper.BindPFlag("websiteListenAddr", cmd.Flags().Lookup("listen-addr"))
		_ = viper.BindPFlag("websiteShowConfigDetails", cmd.Flags().Lookup("show-config-details"))
		_ = viper.BindPFlag("websiteLinkBeaconchain", cmd.Flags().Lookup("link-beaconchain"))
		_ = viper.BindPFlag("websiteLinkEtherscan", cmd.Flags().Lookup("link-etherscan"))
		_ = viper.BindPFlag("websiteRelayURL", cmd.Flags().Lookup("relay-url"))
		_ = viper.BindPFlag("websitePubkeyOverride", cmd.Flags().Lookup("pubkey-override"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		log := common.LogSetup(config.GetBool("logJSON"), config.GetString("logLevel")).WithField("service", "relay/website")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(config.GetString("network"))
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}

		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to Redis
		redisURI := config.GetString("redisURI")
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		relayPubkey := ""
		websitePubkeyOverride := config.GetString("websitePubkeyOverride")
		if websitePubkeyOverride != "" {
			relayPubkey = websitePubkeyOverride
		} else {
			relayPubkey, err = redis.GetRelayConfig(datastore.RedisConfigFieldPubkey)
			if err != nil {
				log.WithError(err).Fatal("failed getting pubkey from Redis")
			}
		}

		// Connect to Postgres
		log.Infof("Connecting to Postgres database...")
		postgresDSN := config.GetString("postgresDSN")
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		websiteListenAddr := config.GetString("websiteListenAddr")
		// Create the website service
		opts := &website.WebserverOpts{
			ListenAddress:     websiteListenAddr,
			RelayPubkeyHex:    relayPubkey,
			NetworkDetails:    networkInfo,
			Redis:             redis,
			DB:                db,
			Log:               log,
			ShowConfigDetails: config.GetBool("websiteShowConfigDetails"),
			LinkBeaconchain:   config.GetString("websiteLinkBeaconchain"),
			LinkEtherscan:     config.GetString("websiteLinkEtherscan"),
			RelayURL:          config.GetString("websiteRelayURL"),
		}

		srv, err := website.NewWebserver(opts)
		if err != nil {
			log.WithError(err).Fatal("failed to create service")
		}

		// Start the server
		log.Infof("Webserver starting on %s ...", websiteListenAddr)
		log.Fatal(srv.StartServer())
	},
}
