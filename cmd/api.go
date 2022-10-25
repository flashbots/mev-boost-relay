package cmd

import (
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/config"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/services/api"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().Bool("json", config.DefaultLogJSON, "log in JSON format instead of text")
	apiCmd.Flags().String("logLevel", config.DefaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")
	apiCmd.Flags().String("log-tag", config.APIDefaultLogTag, "if set, a 'tag' field will be added to all log entries")
	apiCmd.Flags().Bool("debug", config.APIDefaultDebug, "debug logging")
	apiCmd.Flags().String("listen-addr", config.APIDefaultListenAddr, "listen address for webserver")
	apiCmd.Flags().StringSlice("beacon-uris", config.DefaultBeaconURIs, "beacon endpoints")
	apiCmd.Flags().String("redis-uri", config.DefaultRedisURI, "Redis uri")
	apiCmd.Flags().String("db", config.DefaultPostgresDSN, "PostgreSQL DSN")
	apiCmd.Flags().String("secret-key", config.APIDefaultSecretKey, "secret key for signing bids")
	apiCmd.Flags().String("blocksim", config.APIDefaultBlockSim, "URL for block simulator")
	apiCmd.Flags().String("network", config.DefaultNetwork, "Which network to use")
	apiCmd.Flags().Bool("pprof", config.APIDefaultPprofEnabled, "enable pprof API")
	apiCmd.Flags().Bool("internal-api", config.APIDefaultInternalAPIEnabled, "enable internal API (/internal/...)")
}

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Start the API server",
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag(config.KeyLogJSON, cmd.Flags().Lookup("json"))
		_ = viper.BindPFlag(config.KeyLogLevel, cmd.Flags().Lookup("loglevel"))
		_ = viper.BindPFlag(config.KeyAPILogTag, cmd.Flags().Lookup("log-tag"))
		_ = viper.BindPFlag(config.KeyAPILogVersion, cmd.Flags().Lookup("log-version"))
		_ = viper.BindPFlag(config.KeyAPIDebug, cmd.Flags().Lookup("debug"))
		_ = viper.BindPFlag(config.KeyAPIListenAddr, cmd.Flags().Lookup("listen-addr"))
		_ = viper.BindPFlag(config.KeyBeaconNodeURIs, cmd.Flags().Lookup("beacon-uris"))
		_ = viper.BindPFlag(config.KeyRedisURI, cmd.Flags().Lookup("redis-uri"))
		_ = viper.BindPFlag(config.KeyPostgresDSN, cmd.Flags().Lookup("db"))
		_ = viper.BindPFlag(config.KeyAPISecretKey, cmd.Flags().Lookup("secret-key"))
		_ = viper.BindPFlag(config.KeyAPIBlockSimURL, cmd.Flags().Lookup("blocksim"))
		_ = viper.BindPFlag(config.KeyNetwork, cmd.Flags().Lookup("network"))
		_ = viper.BindPFlag(config.KeyAPIPprofEnabled, cmd.Flags().Lookup("pprof"))
		_ = viper.BindPFlag(config.KeyAPIInternalAPI, cmd.Flags().Lookup("internal-api"))
	},
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		logLevel := config.GetString(config.KeyLogLevel)
		if config.GetBool(config.KeyAPIDebug) {
			logLevel = "debug"
		}

		log := common.LogSetup(config.GetBool(config.KeyLogJSON), logLevel).WithFields(logrus.Fields{
			"service": "relay/api",
			"version": Version,
		})

		apiLogTag := config.GetString(config.KeyAPILogTag)
		if apiLogTag != "" {
			log = log.WithField("tag", apiLogTag)
		}
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(config.GetString(config.KeyNetwork))
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon clients and ensure it's synced
		beaconNodeURIs := config.GetStringSlice(config.KeyBeaconNodeURIs)
		if len(beaconNodeURIs) == 0 {
			log.Fatalf("no beacon endpoints specified")
		}
		log.Infof("Using beacon endpoints: %s", strings.Join(beaconNodeURIs, ", "))
		var beaconInstances []beaconclient.IBeaconInstance
		for _, uri := range beaconNodeURIs {
			beaconInstances = append(beaconInstances, beaconclient.NewProdBeaconInstance(log, uri))
		}
		beaconClient := beaconclient.NewMultiBeaconClient(log, beaconInstances)

		// Connect to Redis
		redisURI := config.GetString(config.KeyRedisURI)
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}
		log.Infof("Connected to Redis at %s", redisURI)

		// Connect to Postgres
		postgresDSN := config.GetString(config.KeyPostgresDSN)
		dbURL, err := url.Parse(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("couldn't read db URL")
		}
		log.Infof("Connecting to Postgres database at %s%s ...", dbURL.Host, dbURL.Path)
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s%s", dbURL.Host, dbURL.Path)
		}

		log.Info("Setting up datastore...")
		ds, err := datastore.NewDatastore(log, redis, db)
		if err != nil {
			log.WithError(err).Fatalf("Failed setting up prod datastore")
		}

		apiListenAddr := config.GetString(config.KeyAPIListenAddr)

		opts := api.RelayAPIOpts{
			Log:           log,
			ListenAddr:    apiListenAddr,
			BeaconClient:  beaconClient,
			Datastore:     ds,
			Redis:         redis,
			DB:            db,
			EthNetDetails: *networkInfo,
			BlockSimURL:   config.GetString(config.KeyAPIBlockSimURL),

			ProposerAPI:     true,
			BlockBuilderAPI: true,
			DataAPI:         true,
			InternalAPI:     config.GetBool(config.KeyAPIInternalAPI),
			PprofAPI:        config.GetBool(config.KeyAPIPprofEnabled),
		}

		// Decode the private key
		apiSecretKey := config.GetString(config.KeyAPISecretKey)
		if apiSecretKey == "" {
			log.Warn("No secret key specified, block builder API is disabled")
			opts.BlockBuilderAPI = false
		} else {
			envSkBytes, err := hexutil.Decode(apiSecretKey)
			if err != nil {
				log.WithError(err).Fatal("incorrect secret key provided")
			}
			opts.SecretKey, err = bls.SecretKeyFromBytes(envSkBytes[:])
			if err != nil {
				log.WithError(err).Fatal("incorrect builder API secret key provided")
			}
		}

		// Create the relay service
		log.Info("Setting up relay service...")
		srv, err := api.NewRelayAPI(opts)
		if err != nil {
			log.WithError(err).Fatal("failed to create service")
		}

		// Create a signal handler
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-sigs
			log.Infof("signal received: %s", sig)
			err := srv.StopServer()
			if err != nil {
				log.WithError(err).Fatal("error stopping server")
			}
		}()

		// Start the server
		log.Infof("Webserver starting on %s ...", apiListenAddr)
		err = srv.StartServer()
		if err != nil {
			log.WithError(err).Fatal("server error")
		}
		log.Info("bye")
	},
}
