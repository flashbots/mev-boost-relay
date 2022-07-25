package cmd

import (
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/website"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	websiteDefaultListenAddr = "localhost:9060"
)

var (
	websiteListenAddr  string
	websiteNetwork     string
	websiteRelayPubkey string
)

func init() {
	rootCmd.AddCommand(websiteCmd)
	websiteCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	websiteCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	websiteCmd.Flags().StringVar(&websiteListenAddr, "listen-addr", websiteDefaultListenAddr, "listen address for webserver")
	websiteCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")

	websiteCmd.Flags().StringVar(&websiteRelayPubkey, "relay-pubkey", "", "relay pubkey")
	websiteCmd.MarkFlagRequired("relay-pubkey")

	websiteCmd.Flags().StringVar(&websiteNetwork, "network", "", "Which network to use")
	websiteCmd.MarkFlagRequired("network")
}

var websiteCmd = &cobra.Command{
	Use:   "website",
	Short: "Start the website server",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/website")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(websiteNetwork)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}

		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to Redis
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		// Create the website service
		opts := &website.WebserverOpts{
			ListenAddress:  websiteListenAddr,
			RelayPubkeyHex: websiteRelayPubkey,
			NetworkDetails: networkInfo,
			Redis:          redis,
			Log:            log,
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
