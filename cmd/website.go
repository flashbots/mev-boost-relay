package cmd

import (
	"net/url"
	"os"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/services/website"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	websiteDefaultListenAddr        = common.GetEnv("LISTEN_ADDR", "localhost:9060")
	websiteDefaultShowConfigDetails = os.Getenv("SHOW_CONFIG_DETAILS") == "1"
	websiteDefaultLinkBeaconchain   = common.GetEnv("LINK_BEACONCHAIN", "https://beaconcha.in")
	websiteDefaultLinkEtherscan     = common.GetEnv("LINK_ETHERSCAN", "https://etherscan.io")
	websiteDefaultLinkDataAPI       = common.GetEnv("LINK_DATA_API", "")
	websiteDefaultRelayURL          = common.GetEnv("RELAY_URL", "")

	websiteListenAddr        string
	websitePubkeyOverride    string
	websiteShowConfigDetails bool

	websiteLinkBeaconchain string
	websiteLinkEtherscan   string
	websiteLinkDataAPI     string
	websiteRelayURL        string
)

func init() {
	rootCmd.AddCommand(websiteCmd)
	websiteCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	websiteCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	websiteCmd.Flags().StringVar(&websiteListenAddr, "listen-addr", websiteDefaultListenAddr, "listen address for webserver")
	websiteCmd.Flags().StringVar(&redisURI, "redis-uri", defaultRedisURI, "redis uri")
	websiteCmd.Flags().StringVar(&redisReadonlyURI, "redis-readonly-uri", defaultRedisReadonlyURI, "redis readonly uri")
	websiteCmd.Flags().StringVar(&postgresDSN, "db", defaultPostgresDSN, "PostgreSQL DSN")
	websiteCmd.Flags().StringVar(&websitePubkeyOverride, "pubkey-override", os.Getenv("PUBKEY_OVERRIDE"), "override for public key")

	websiteCmd.Flags().StringVar(&network, "network", defaultNetwork, "Which network to use")
	websiteCmd.Flags().BoolVar(&websiteShowConfigDetails, "show-config-details", websiteDefaultShowConfigDetails, "show config details")
	websiteCmd.Flags().StringVar(&websiteLinkBeaconchain, "link-beaconchain", websiteDefaultLinkBeaconchain, "url for beaconcha.in")
	websiteCmd.Flags().StringVar(&websiteLinkEtherscan, "link-etherscan", websiteDefaultLinkEtherscan, "url for etherscan")
	websiteCmd.Flags().StringVar(&websiteLinkDataAPI, "link-data-api", websiteDefaultLinkDataAPI, "origin url for data api (https://domain:port)")
	websiteCmd.Flags().StringVar(&websiteRelayURL, "relay-url", websiteDefaultRelayURL, "full url for the relay (https://pubkey@host)")
}

var websiteCmd = &cobra.Command{
	Use:   "website",
	Short: "Start the website server",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		log := common.LogSetup(logJSON, logLevel).WithFields(logrus.Fields{
			"service": "relay/website",
			"version": Version,
		})
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}

		log.Infof("Using network: %s", networkInfo.Name)
		log.Debug(networkInfo.String())

		// Connect to Redis
		if redisReadonlyURI == "" {
			log.Infof("Connecting to Redis at %s ...", redisURI)
		} else {
			log.Infof("Connecting to Redis at %s / readonly: %s ...", redisURI, redisReadonlyURI)
		}
		redis, err := datastore.NewRedisCache(networkInfo.Name, redisURI, redisReadonlyURI)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		relayPubkey := ""
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
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		// Create the website service
		opts := &website.WebserverOpts{
			ListenAddress:     websiteListenAddr,
			RelayPubkeyHex:    relayPubkey,
			NetworkDetails:    networkInfo,
			Redis:             redis,
			DB:                db,
			Log:               log,
			ShowConfigDetails: websiteShowConfigDetails,
			LinkBeaconchain:   websiteLinkBeaconchain,
			LinkEtherscan:     websiteLinkEtherscan,
			LinkDataAPI:       websiteLinkDataAPI,
			RelayURL:          websiteRelayURL,
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
