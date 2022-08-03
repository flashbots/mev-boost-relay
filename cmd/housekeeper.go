package cmd

import (
	"os"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/boost-relay/services/housekeeper"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(housekeeperCmd)
	housekeeperCmd.Flags().BoolVar(&logJSON, "json", defaultLogJSON, "log in JSON format instead of text")
	housekeeperCmd.Flags().StringVar(&logLevel, "loglevel", defaultLogLevel, "log-level: trace, debug, info, warn/warning, error, fatal, panic")

	housekeeperCmd.Flags().StringVar(&beaconNodeURI, "beacon-uri", defaultBeaconURI, "beacon endpoint")
	housekeeperCmd.Flags().StringVar(&redisURI, "redis-uri", defaultredisURI, "redis uri")
	housekeeperCmd.Flags().StringVar(&postgresDSN, "db", os.Getenv("POSTGRES_DSN"), "PostgreSQL DSN")

	housekeeperCmd.Flags().StringVar(&network, "network", "", "Which network to use")
	housekeeperCmd.MarkFlagRequired("network")
}

var housekeeperCmd = &cobra.Command{
	Use:   "housekeeper",
	Short: "Service that runs in the background and does various housekeeping (removing old bids, updating proposer duties, saving metrics, etc.)",
	Run: func(cmd *cobra.Command, args []string) {
		var err error

		common.LogSetup(logJSON, logLevel)
		log := logrus.WithField("module", "cmd/metrics-saver")
		log.Infof("boost-relay %s", Version)

		networkInfo, err := common.NewEthNetworkDetails(network)
		if err != nil {
			log.WithError(err).Fatalf("error getting network details")
		}
		log.Infof("Using network: %s", networkInfo.Name)

		// Connect to beacon client and ensure it's synced
		log.Infof("Using beacon endpoint: %s", beaconNodeURI)
		beaconClient := beaconclient.NewProdBeaconClient(log, beaconNodeURI)

		// Connect to Redis and setup the datastore
		redis, err := datastore.NewRedisCache(redisURI, networkInfo.Name)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Redis at %s", redisURI)
		}

		log.Infof("Connecting to Postgres database...")
		db, err := database.NewDatabaseService(postgresDSN)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database")
		}

		ds, err := datastore.NewDatastore(log, redis, db)
		if err != nil {
			log.WithError(err).Fatalf("Failed to connect to Postgres database at %s", postgresDSN)
		}

		opts := &housekeeper.HousekeeperOpts{
			Log:          log,
			Redis:        redis,
			Datastore:    ds,
			BeaconClient: beaconClient,
		}
		service := housekeeper.NewHousekeeper(opts)
		log.Info("Starting service...")
		err = service.Start()
		log.WithError(err).Fatalf("Failed to start housekeeper")
	},
}

// type metricsSaver struct {
// 	log          *logrus.Entry
// 	beaconClient beaconclient.BeaconNodeClient
// 	redis        *datastore.RedisCache
// 	db           *database.DatabaseService

// 	headSlot     uint64
// 	currentEpoch uint64

// 	// Metrics helpers
// 	validatorsKnownTotal        uint64
// 	validatorRegistrationsTotal uint64
// }

// func (m *metricsSaver) start() {
// 	syncStatus, err := m.beaconClient.SyncStatus()
// 	if err != nil {
// 		m.log.WithError(err).Fatal("Failed to get beaconclient sync status")
// 	}
// 	if syncStatus.IsSyncing {
// 		m.log.Fatal("beacon node is syncing")
// 	}

// 	headSlot := syncStatus.HeadSlot
// 	m.processNewSlot(headSlot)

// 	// Start regular validator updates
// 	go m.startKnownValidatorUpdates()

// 	// Start regular slot updates
// 	c := make(chan uint64)
// 	go m.beaconClient.SubscribeToHeadEvents(c)
// 	for {
// 		headSlot := <-c
// 		m.processNewSlot(headSlot)
// 	}
// }

// func (m *metricsSaver) processNewSlot(headSlot uint64) {
// 	if headSlot <= m.headSlot {
// 		return
// 	}

// 	if m.headSlot > 0 { // only check subsequent events after startup
// 		for s := m.headSlot + 1; s < headSlot; s++ {
// 			m.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
// 			go m.saveSlotSummary(s)
// 		}
// 	}

// 	go m.saveSlotSummary(headSlot)

// 	m.headSlot = headSlot
// 	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)

// 	m.log.WithFields(logrus.Fields{
// 		"epoch":              currentEpoch,
// 		"slotHead":           headSlot,
// 		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
// 	}).Infof("updated headSlot to %d", headSlot)

// 	// if m.currentEpoch > 0 {
// 	if m.currentEpoch > 0 && currentEpoch > m.currentEpoch {
// 		go m.saveEpochSummary(currentEpoch)
// 	}
// 	m.currentEpoch = currentEpoch
// }

// func (m *metricsSaver) saveSlotSummary(slot uint64) {
// 	m.log.Infof("saving slot summary for slot: %d", slot)

// 	// slotSummary := common.SlotSummary{
// 	// 	Slot:  slot,
// 	// 	Epoch: slot / uint64(common.SlotsPerEpoch),
// 	// }
// }

// func (m *metricsSaver) valToInt(vals map[string]string, field string) uint64 {
// 	val, found := vals[field]
// 	if !found {
// 		return 0
// 	}

// 	ret, err := strconv.ParseUint(val, 10, 64)
// 	if err != nil {
// 		m.log.WithError(err).Errorf("failed to parse %s: %s", field, val)
// 		return 0
// 	}

// 	return ret
// }

// func (m *metricsSaver) saveEpochSummary(epoch uint64) {
// 	m.log.Infof("saving epoch summary for epoch: %d", epoch)
// 	vals, err := m.redis.GetEpochSummary(epoch)
// 	if err != nil {
// 		m.log.WithError(err).Errorf("failed to get epoch summary from redis for epoch %d", epoch)
// 		return
// 	}

// 	epochSummary := common.EpochSummary{
// 		Epoch:              epoch,
// 		SlotFirst:          epoch * uint64(common.SlotsPerEpoch),
// 		SlotLast:           (epoch+1)*uint64(common.SlotsPerEpoch) - 1,
// 		SlotFirstProcessed: m.valToInt(vals, "slot_first_processed"),
// 		SlotLastProcessed:  m.valToInt(vals, "slot_last_processed"),

// 		ValidatorsKnownTotal:                     m.validatorsKnownTotal,
// 		ValidatorRegistrationsTotal:              m.validatorRegistrationsTotal,
// 		ValidatorRegistrationsSaved:              m.valToInt(vals, "validator_registrations_saved"),
// 		ValidatorRegistrationsReceviedUnverified: m.valToInt(vals, "validator_registrations_received_unverified"),

// 		NumRegisterValidatorRequests: m.valToInt(vals, "num_register_validator_requests"),
// 		NumGetHeaderRequests:         m.valToInt(vals, "num_get_header_requests"),
// 		NumGetPayloadRequests:        m.valToInt(vals, "num_get_payload_requests"),

// 		NumHeaderSentOk:       m.valToInt(vals, "num_header_sent_ok"),
// 		NumHeaderSent204:      m.valToInt(vals, "num_header_sent_204"),
// 		NumPayloadSent:        m.valToInt(vals, "num_payload_sent"),
// 		NumBuilderBidReceived: m.valToInt(vals, "num_builder_bid_received"),
// 	}

// 	epochSummary.IsComplete = epochSummary.SlotFirst == epochSummary.SlotFirstProcessed && epochSummary.SlotLast == epochSummary.SlotLastProcessed

// 	err = m.db.SaveEpochSummary(epochSummary)
// 	if err != nil {
// 		m.log.WithError(err).Errorf("failed to save epoch summary to database for epoch %d", epoch)
// 	}
// }

// func (m *metricsSaver) startKnownValidatorUpdates() {
// 	for {
// 		// Refresh known validators
// 		knownValidators, err := m.redis.GetKnownValidators()
// 		if err != nil {
// 			m.log.WithError(err).Error("Failed to get known validators")
// 		} else {
// 			atomic.StoreUint64(&m.validatorsKnownTotal, uint64(len(knownValidators)))
// 		}

// 		numRegisteredValidators, err := m.redis.NumRegisteredValidators()
// 		if err != nil {
// 			m.log.WithError(err).Error("Failed to get known validators")
// 		} else {
// 			atomic.StoreUint64(&m.validatorRegistrationsTotal, uint64(numRegisteredValidators))
// 		}

// 		m.log.WithFields(logrus.Fields{
// 			"numKnownValidators":      atomic.LoadUint64(&m.validatorsKnownTotal),
// 			"numRegisteredValidators": atomic.LoadUint64(&m.validatorRegistrationsTotal),
// 		}).Info("updated validators")

// 		// Wait for some time
// 		time.Sleep(common.DurationPerEpoch / 2)
// 	}
// }
