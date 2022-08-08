package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/services/website"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	websiteDefaultListenAddr = "localhost:9060"
)

var (
	websiteListenAddr string
)

func init() {
	rootCmd.AddCommand(websiteCmd)
	websiteCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	websiteCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	websiteCmd.Flags().StringVar(&websiteListenAddr, "listen-addr", websiteDefaultListenAddr, "listen address for webserver")
	websiteCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	websiteCmd.Flags().StringVar(&postgresDSN, "db", "", "PostgreSQL DSN")

	websiteCmd.Flags().StringVar(&network, "network", "", "Which network to use")
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

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}

		log.Infof("Using network: %s", networkInfo.Name)

		// Prepare context with cancellation
		ctx, cancel := context.WithCancel(context.Background())

		// Connect to Redis
		redis, err := datastore.NewRedisCache(ctx, redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		relayPubkey, err := redis.GetRelayConfig(ctx, datastore.FieldPubkey)
		if err != nil {
			log.WithError(err).Fatal("failed getting publey from Redis")
		}

		// Connect to Postgres
		log.Infof("connecting to Postgres database...")
		db, err := database.NewDatabaseService(ctx, postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s", postgresDSN)
		}

		// Create the website service
		opts := &website.WebserverOpts{
			ListenAddress:  websiteListenAddr,
			RelayPubkeyHex: relayPubkey,
			NetworkDetails: networkInfo,
			Redis:          redis,
			DB:             db,
			Log:            log,
		}

		srv, err := website.NewWebserver(opts)
		if err != nil {
			log.WithError(err).Fatal("failed to create service")
		}

		// Handle graceful shutdown
		done := make(chan struct{}, 1)
		go func() {
			shutdown := make(chan os.Signal, 1)
			signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
			<-shutdown
			signal.Stop(shutdown)

			log.Warn("shutting down website server....")
			srv.Stop(ctx)
			cancel()
			close(done)
		}()
		// Start the server
		log.Infof("starting website webserver on %s ...", websiteListenAddr)
		if err = srv.StartServer(ctx); err != nil {
			log.WithError(err).Fatalf("failed to start website server")
		}
		<-done
		log.Warn("good bye")
	},
}
