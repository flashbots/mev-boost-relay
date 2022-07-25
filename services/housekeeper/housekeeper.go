// Package housekeeper contains the service doing all required regular tasks
//
// - Update known validators
// - Updating proposer duties
// - Saving metrics
// - Deleting old bids
// - ...
package housekeeper

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/flashbots/boost-relay/beaconclient"
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/datastore"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

type HousekeeperOpts struct {
	Log          *logrus.Entry
	Redis        *datastore.RedisCache
	Datastore    datastore.Datastore
	BeaconClient *beaconclient.ProdBeaconClient
}

type Housekeeper struct {
	opts *HousekeeperOpts
	log  *logrus.Entry

	datastore    datastore.Datastore
	redis        *datastore.RedisCache
	beaconClient *beaconclient.ProdBeaconClient

	isStarted                uberatomic.Bool
	isUpdatingProposerDuties uberatomic.Bool

	headSlot     uint64
	currentEpoch uint64

	// feature flags
	enableQueryProposerDutiesForNextEpoch bool
}

func NewHousekeeper(opts *HousekeeperOpts) *Housekeeper {
	server := &Housekeeper{
		opts:         opts,
		log:          opts.Log.WithField("module", "housekeeper"),
		redis:        opts.Redis,
		datastore:    opts.Datastore,
		beaconClient: opts.BeaconClient,
	}

	if os.Getenv("ENABLE_QUERY_PROPOSER_DUTIES_NEXT_EPOCH") != "" {
		server.log.Warn("env: ENABLE_QUERY_PROPOSER_DUTIES_NEXT_EPOCH - querying proposer duties for current + next epoch")
		server.enableQueryProposerDutiesForNextEpoch = true
	}

	return server
}

// Start starts the housekeeper service, blocking
func (hk *Housekeeper) Start() (err error) {
	defer hk.isStarted.Store(false)
	if hk.isStarted.Swap(true) {
		return errors.New("server was already started")
	}

	// Check beacon-node sync status, process current slot and start slot updates
	syncStatus, err := hk.beaconClient.SyncStatus()
	if err != nil {
		return err
	}
	if syncStatus.IsSyncing {
		return errors.New("beacon node is syncing")
	}

	// Start regular known validator updates
	go func() {
		for {
			hk.updateKnownValidators()
			time.Sleep(common.DurationPerEpoch / 2)
		}
	}()

	// Process the current slot
	headSlot := syncStatus.HeadSlot
	hk.processNewSlot(headSlot)

	// Start regular slot updates
	c := make(chan uint64)
	go hk.beaconClient.SubscribeToHeadEvents(c)
	for {
		headSlot := <-c
		hk.processNewSlot(headSlot)
	}
}

func (hk *Housekeeper) processNewSlot(headSlot uint64) {
	if headSlot <= hk.headSlot {
		return
	}

	if hk.headSlot > 0 {
		for s := hk.headSlot + 1; s < headSlot; s++ {
			hk.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)
	hk.log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)

	// Update proposer duties twice per epoch
	if hk.headSlot == 0 || headSlot%uint64(common.SlotsPerEpoch/2) == 0 {
		go hk.updateProposerDuties()
	}

	hk.headSlot = headSlot
	hk.currentEpoch = currentEpoch
}

func (hk *Housekeeper) updateKnownValidators() {
	// Query beacon node for known validators
	hk.log.Debug("Querying validators from beacon node... (this may take a while)")
	validators, err := hk.beaconClient.FetchValidators()
	if err != nil {
		hk.log.WithError(err).Fatal("failed to fetch validators from beacon node")
		return
	}

	hk.log.WithField("numKnownValidators", len(validators)).Infof("updateKnownValidators: received %d validators from BN", len(validators))
	go hk.redis.SetStats("validators_known_total", fmt.Sprint(len(validators)))

	// Update Redis with validators
	hk.log.Debug("Writing to Redis...")

	// var last beaconclient.ValidatorResponseEntry
	for _, v := range validators {
		// last = v
		err = hk.redis.SetKnownValidator(types.PubkeyHex(v.Validator.Pubkey), v.Index)
		if err != nil {
			hk.log.WithError(err).WithField("pubkey", v.Validator.Pubkey).Fatal("failed to set known validator in Redis")
		}
	}

	// hk.log.Info("Updated Redis ", last.Index, " ", last.Validator.Pubkey)
}

func (hk *Housekeeper) updateProposerDuties() {
	// Should only happen once at a time
	defer hk.isUpdatingProposerDuties.Store(false)
	if hk.isUpdatingProposerDuties.Swap(true) {
		return
	}

	epochFrom := hk.currentEpoch
	epochTo := epochFrom
	if hk.enableQueryProposerDutiesForNextEpoch {
		epochTo = epochFrom + 1
	}

	log := hk.log.WithFields(logrus.Fields{
		"epochFrom": epochFrom,
		"epochTo":   epochTo,
	})
	log.Debug("updating proposer duties...")

	r, err := hk.beaconClient.GetProposerDuties(epochFrom)
	if err != nil {
		log.WithError(err).Fatal("failed to get proposer duties")
		return
	}

	entries := r.Data

	if hk.enableQueryProposerDutiesForNextEpoch {
		r2, err := hk.beaconClient.GetProposerDuties(epochTo)
		if err == nil {
			entries = append(entries, r2.Data...)
		} else {
			hk.log.WithError(err).Error("failed to get proposer duties for next epoch")
		}
	}

	// Result of parallel Redis requests
	type result struct {
		val types.BuilderGetValidatorsResponseEntry
		err error
	}

	// Scatter requests to Redis to get validator registrations
	c := make(chan result, len(entries))
	for i := 0; i < cap(c); i++ {
		go func(duty beaconclient.ProposerDutiesResponseData) {
			reg, err := hk.datastore.GetValidatorRegistration(types.NewPubkeyHex(duty.Pubkey))
			c <- result{types.BuilderGetValidatorsResponseEntry{
				Slot:  duty.Slot,
				Entry: reg,
			}, err}
		}(entries[i])
	}

	// Gather results
	proposerDuties := make([]types.BuilderGetValidatorsResponseEntry, 0)
	for i := 0; i < cap(c); i++ {
		res := <-c
		if res.err != nil {
			log.WithError(err).Fatal("error in loading validator registration from redis")
		} else if res.val.Entry != nil { // only if a known registration
			proposerDuties = append(proposerDuties, res.val)
		}
	}

	hk.redis.SetProposerDuties(proposerDuties)
	log.WithField("duties", len(proposerDuties)).Info("proposer duties updated")
}
