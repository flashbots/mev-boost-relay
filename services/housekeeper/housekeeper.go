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
	"sort"
	"strings"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

type HousekeeperOpts struct {
	Log          *logrus.Entry
	Redis        *datastore.RedisCache
	DB           database.IDatabaseService
	BeaconClient beaconclient.IMultiBeaconClient
}

type Housekeeper struct {
	opts *HousekeeperOpts
	log  *logrus.Entry

	redis        *datastore.RedisCache
	db           database.IDatabaseService
	beaconClient beaconclient.IMultiBeaconClient

	isStarted                uberatomic.Bool
	isUpdatingProposerDuties uberatomic.Bool
	proposerDutiesSlot       uint64

	headSlot uberatomic.Uint64

	lastValdatorUpdateSlot uberatomic.Uint64
	lastValdatorIsUpdating uberatomic.Bool

	proposersAlreadySaved map[uint64]string // to avoid repeating redis writes
}

var ErrServerAlreadyStarted = errors.New("server was already started")

func NewHousekeeper(opts *HousekeeperOpts) *Housekeeper {
	server := &Housekeeper{
		opts:                  opts,
		log:                   opts.Log,
		redis:                 opts.Redis,
		db:                    opts.DB,
		beaconClient:          opts.BeaconClient,
		proposersAlreadySaved: make(map[uint64]string),
	}

	return server
}

// Start starts the housekeeper service, blocking
func (hk *Housekeeper) Start() (err error) {
	defer hk.isStarted.Store(false)
	if hk.isStarted.Swap(true) {
		return ErrServerAlreadyStarted
	}

	// Get best beacon-node status by head slot, process current slot and start slot updates
	bestSyncStatus, err := hk.beaconClient.BestSyncStatus()
	if err != nil {
		return err
	}

	// Start initial tasks
	go hk.updateValidatorRegistrationsInRedis()

	// Process the current slot
	hk.processNewSlot(bestSyncStatus.HeadSlot)

	// Start regular slot updates
	c := make(chan beaconclient.HeadEventData)
	hk.beaconClient.SubscribeToHeadEvents(c)
	for {
		headEvent := <-c
		hk.processNewSlot(headEvent.Slot)
	}
}

func (hk *Housekeeper) processNewSlot(headSlot uint64) {
	prevHeadSlot := hk.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return
	}
	hk.headSlot.Store(headSlot)

	// kick of a possible validator update
	go hk.updateKnownValidators()

	log := hk.log.WithFields(logrus.Fields{
		"headSlot":     headSlot,
		"headSlotPos":  common.SlotPos(headSlot),
		"prevHeadSlot": prevHeadSlot,
	})

	// Print any missed slots
	if prevHeadSlot > 0 {
		for s := prevHeadSlot + 1; s < headSlot; s++ {
			log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// Update proposer duties
	go hk.updateProposerDuties(headSlot)

	// Set headSlot in redis (for the website)
	err := hk.redis.SetStats(datastore.RedisStatsFieldLatestSlot, headSlot)
	if err != nil {
		log.WithError(err).Error("failed to set stats")
	}

	currentEpoch := headSlot / common.SlotsPerEpoch
	log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotStartNextEpoch": (currentEpoch + 1) * common.SlotsPerEpoch,
	}).Infof("updated headSlot to %d", headSlot)
}

// updateKnownValidators queries the full list of known validators from the beacon node
// and stores it in redis. For the CL client this is an expensive operation and takes a bunch
// of resources. This is why we schedule the requests for slot 4 and 20 of every epoch,
// 6 seconds into the slot (on suggestion of @potuz). It's also run once at startup.
func (hk *Housekeeper) updateKnownValidators() {
	// Ensure there's only one at a time
	if isUpdating := hk.lastValdatorIsUpdating.Swap(true); isUpdating {
		return
	}
	defer hk.lastValdatorIsUpdating.Store(false)

	// Load data and prepare logs
	headSlot := hk.headSlot.Load()
	headSlotPos := common.SlotPos(headSlot) // 1-based position in epoch (32 slots, 1..32)
	lastUpdateSlot := hk.lastValdatorUpdateSlot.Load()
	log := hk.log.WithFields(logrus.Fields{
		"headSlot":       headSlot,
		"headSlotPos":    headSlotPos,
		"lastUpdateSlot": lastUpdateSlot,
		"method":         "updateKnownValidators",
	})
	log.Debug("updateKnownValidators init")

	// Abort if we already had this slot
	if headSlot <= lastUpdateSlot {
		return
	}

	// Minimum amount of slots between updates
	slotsSinceLastUpdate := headSlot - lastUpdateSlot
	if slotsSinceLastUpdate < 6 {
		return
	}

	// Force update after a longer time since last successful update
	forceUpdate := slotsSinceLastUpdate > 32

	// Proceed only if forced, or on slot-position 4 or 20
	if !forceUpdate && headSlotPos != 4 && headSlotPos != 20 {
		return
	}

	// Wait for 6s into the slot
	time.Sleep(6 * time.Second)

	//
	// Execute update now
	//
	// Query beacon node for known validators
	log.Info("Querying validators from beacon node... (this may take a while)")
	timeStartFetching := time.Now()
	validators, err := hk.beaconClient.GetStateValidators(beaconclient.StateIDHead) // head is fastest
	if err != nil {
		log.WithError(err).Error("failed to fetch validators from all beacon nodes")
		return
	}

	numValidators := len(validators)
	log = log.WithField("numKnownValidators", numValidators)
	log.WithField("durationFetchValidatorsMs", time.Since(timeStartFetching).Milliseconds()).Infof("received validators from beacon-node")

	// Store total number of validators
	err = hk.redis.SetStats(datastore.RedisStatsFieldValidatorsTotal, fmt.Sprint(numValidators))
	if err != nil {
		log.WithError(err).Error("failed to set stats for RedisStatsFieldValidatorsTotal")
	}

	// At this point, consider the update successful
	hk.lastValdatorUpdateSlot.Store(headSlot)

	// Update Redis with validators
	log.Debug("Writing to Redis...")
	timeStartWriting := time.Now()

	// This process can take very long, that's why it prints a log line every 10k validators
	printCounter := len(hk.proposersAlreadySaved) == 0 // only do this on service startup

	i := 0
	newValidators := 0
	for _, validator := range validators {
		i++
		if printCounter && i%10000 == 0 {
			log.Debugf("writing to redis: %d / %d", i, numValidators)
		}

		// avoid resaving if index->pubkey mapping is the same
		prevPubkeyForIndex := hk.proposersAlreadySaved[validator.Index]
		if prevPubkeyForIndex == validator.Validator.Pubkey {
			continue
		}

		err := hk.redis.SetKnownValidator(types.PubkeyHex(validator.Validator.Pubkey), validator.Index)
		if err != nil {
			log.WithError(err).WithField("pubkey", validator.Validator.Pubkey).Error("failed to set known validator in Redis")
		} else {
			hk.proposersAlreadySaved[validator.Index] = validator.Validator.Pubkey
			newValidators++
		}
	}

	log.WithFields(logrus.Fields{
		"durationRedisWrite": time.Since(timeStartWriting).Seconds(),
		"newValidators":      newValidators,
	}).Info("updateKnownValidators done")
}

func (hk *Housekeeper) updateProposerDuties(headSlot uint64) {
	// Should only happen once at a time
	if hk.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer hk.isUpdatingProposerDuties.Store(false)

	slotsForHalfAnEpoch := common.SlotsPerEpoch / 2
	if headSlot%slotsForHalfAnEpoch != 0 && headSlot-hk.proposerDutiesSlot < slotsForHalfAnEpoch {
		return
	}

	epoch := headSlot / common.SlotsPerEpoch

	log := hk.log.WithFields(logrus.Fields{
		"epochFrom": epoch,
		"epochTo":   epoch + 1,
	})
	log.Debug("updating proposer duties...")

	// Query current epoch
	r, err := hk.beaconClient.GetProposerDuties(epoch)
	if err != nil {
		log.WithError(err).Error("failed to get proposer duties for all beacon nodes")
		return
	}
	entries := r.Data

	// Query next epoch
	r2, err := hk.beaconClient.GetProposerDuties(epoch + 1)
	if err != nil {
		log.WithError(err).Error("failed to get proposer duties for next epoch for all beacon nodes")
	} else if r2 != nil {
		entries = append(entries, r2.Data...)
	}

	// Get registrations from database
	pubkeys := []string{}
	for _, entry := range entries {
		pubkeys = append(pubkeys, entry.Pubkey)
	}
	validatorRegistrationEntries, err := hk.db.GetValidatorRegistrationsForPubkeys(pubkeys)
	if err != nil {
		log.WithError(err).Error("failed to get validator registrations")
		return
	}

	// Convert db entries to signed validator registration type
	signedValidatorRegistrations := make(map[string]*types.SignedValidatorRegistration)
	for _, regEntry := range validatorRegistrationEntries {
		signedEntry, err := regEntry.ToSignedValidatorRegistration()
		if err != nil {
			log.WithError(err).Error("failed to convert validator registration entry to signed validator registration")
			continue
		}
		signedValidatorRegistrations[regEntry.Pubkey] = signedEntry
	}

	// Prepare proposer duties
	proposerDuties := []common.BuilderGetValidatorsResponseEntry{}
	for _, duty := range entries {
		reg := signedValidatorRegistrations[duty.Pubkey]
		if reg != nil {
			proposerDuties = append(proposerDuties, common.BuilderGetValidatorsResponseEntry{
				Slot:           duty.Slot,
				ValidatorIndex: duty.ValidatorIndex,
				Entry:          reg,
			})
		}
	}

	// Save duties to Redis
	err = hk.redis.SetProposerDuties(proposerDuties)
	if err != nil {
		log.WithError(err).Error("failed to set proposer duties")
		return
	}
	hk.proposerDutiesSlot = headSlot

	// Pretty-print
	_duties := make([]string, len(proposerDuties))
	for i, duty := range proposerDuties {
		_duties[i] = fmt.Sprint(duty.Slot)
	}
	sort.Strings(_duties)
	log.WithField("numDuties", len(_duties)).Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}

// updateValidatorRegistrationsInRedis saves all latest validator registrations from the database to Redis
func (hk *Housekeeper) updateValidatorRegistrationsInRedis() {
	regs, err := hk.db.GetLatestValidatorRegistrations(true)
	if err != nil {
		hk.log.WithError(err).Error("failed to get latest validator registrations")
		return
	}

	hk.log.Infof("updating %d validator registrations in Redis...", len(regs))
	timeStarted := time.Now()

	for _, reg := range regs {
		err = hk.redis.SetValidatorRegistrationTimestampIfNewer(types.PubkeyHex(reg.Pubkey), reg.Timestamp)
		if err != nil {
			hk.log.WithError(err).Error("failed to set validator registration")
			continue
		}
	}
	hk.log.Infof("updating %d validator registrations in Redis done - %f sec", len(regs), time.Since(timeStarted).Seconds())
}
