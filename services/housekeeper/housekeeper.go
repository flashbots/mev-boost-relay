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
	"net/http"
	_ "net/http/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/flashbots/mev-boost-relay/mevcommitclient"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

type HousekeeperOpts struct {
	Log          *logrus.Entry
	Redis        *datastore.RedisCache
	DB           database.IDatabaseService
	BeaconClient beaconclient.IMultiBeaconClient

	PprofAPI           bool
	PprofListenAddress string

	MevCommitClient mevcommitclient.IMevCommitClient
}

type Housekeeper struct {
	opts *HousekeeperOpts
	log  *logrus.Entry

	redis        *datastore.RedisCache
	db           database.IDatabaseService
	beaconClient beaconclient.IMultiBeaconClient

	pprofAPI           bool
	pprofListenAddress string

	isStarted                uberatomic.Bool
	isUpdatingProposerDuties uberatomic.Bool
	proposerDutiesSlot       uint64

	headSlot uberatomic.Uint64

	mevCommitClient mevcommitclient.IMevCommitClient

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
		pprofAPI:              opts.PprofAPI,
		pprofListenAddress:    opts.PprofListenAddress,
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

	// Start pprof API, if requested
	if hk.pprofAPI {
		go hk.startPprofAPI()
	}

	// Start initial tasks
	go hk.updateValidatorRegistrationsInRedis()
	go hk.monitorMevCommitBuilderRegistrations()

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

func (hk *Housekeeper) startPprofAPI() {
	r := mux.NewRouter()
	hk.log.Infof("Starting pprof API at %s", hk.pprofListenAddress)
	r.PathPrefix("/debug/pprof/").Handler(http.DefaultServeMux)
	srv := http.Server{ //nolint:gosec
		Addr:    hk.pprofListenAddress,
		Handler: r,
	}
	err := srv.ListenAndServe()
	if err != nil {
		hk.log.WithError(err).Error("failed to start pprof API")
	}
}

func (hk *Housekeeper) processNewSlot(headSlot uint64) {
	prevHeadSlot := hk.headSlot.Load()
	if headSlot <= prevHeadSlot {
		return
	}
	hk.headSlot.Store(headSlot)

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
	go hk.updateMevCommitValidatorRegistrations(headSlot)
	go hk.cleanupMevCommitBuilderRegistrations()

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

	hk.UpdateProposerDutiesWithoutChecks(headSlot)
}

func (hk *Housekeeper) monitorMevCommitBuilderRegistrations() {
	newBuilderRegistered, builderUnregistered, err := hk.mevCommitClient.ListenForBuildersEvents()
	if err != nil {
		hk.log.WithError(err).Error("failed to subscribe to mev-commit builder registered events")
		return
	}

	for {
		select {
		case builder := <-newBuilderRegistered:
			hk.log.WithField("builder", builder).Info("new builder registered")
			err := hk.redis.SetMevCommitBlockBuilder(builder)
			if err != nil {
				hk.log.WithError(err).Error("failed to set mev-commit builder registration")
			}
		case builderAddress := <-builderUnregistered:
			entries, err := hk.redis.GetMevCommitBlockBuilders()
			if err != nil {
				hk.log.WithError(err).Error("failed to get mev-commit block builders from Redis")
				return
			}
			for _, entry := range entries {
				if entry.EOAAddress == builderAddress {
					hk.log.WithField("builder", builderAddress).Info("builder unregistered")
					err := hk.redis.DeleteMevCommitValidatorRegistration(common.PubkeyHex(entry.Pubkey))
					if err != nil {
						hk.log.WithError(err).Errorf("failed to delete mev-commit block builder %s", builderAddress)
					}
					break
				}
			}
		}
	}

	hk.log.Info("mev-commit builder registration monitoring stopped")
}

func (hk *Housekeeper) cleanupMevCommitBuilderRegistrations() {
	entries, err := hk.redis.GetMevCommitBlockBuilders()
	if err != nil {
		hk.log.WithError(err).Error("failed to get mev-commit block builders from Redis")
		return
	}

	for _, builder := range entries {
		isRegistered, err := hk.mevCommitClient.IsBuilderValid(builder.EOAAddress)
		if err != nil {
			hk.log.WithError(err).Errorf("failed to check if builder %s is registered", builder.Pubkey)
			continue
		}
		if !isRegistered {
			err := hk.redis.DeleteMevCommitValidatorRegistration(common.PubkeyHex(builder.Pubkey))
			if err != nil {
				hk.log.WithError(err).Errorf("failed to delete mev-commit validator registration for builder %s", builder.Pubkey)
			} else {
				hk.log.WithField("builder", builder.Pubkey).Info("deleted mev-commit validator registration for inactive builder")
			}
		}
	}

	hk.log.Info("completed cleanup of mev-commit builder registrations")
}

func (hk *Housekeeper) UpdateProposerDutiesWithoutChecks(headSlot uint64) {
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
	signedValidatorRegistrations := make(map[string]*builderApiV1.SignedValidatorRegistration)
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
		_duties[i] = strconv.FormatUint(duty.Slot, 10)
	}
	sort.Strings(_duties)
	log.WithField("numDuties", len(_duties)).Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}

// When the update is triggered, we store registered validators in Redis for an the current and next epoch.
// This allows us to maintain 1 epoch in advance, which is enough to check if a validator is registered for a given epoch.
func (hk *Housekeeper) updateMevCommitValidatorRegistrations(headSlot uint64) {
	// Only update once per epoch - at the epoch start of the epoch
	if headSlot%common.SlotsPerEpoch != 0 {
		return
	}

	epoch := headSlot / common.SlotsPerEpoch

	duties, err := hk.beaconClient.GetProposerDuties(epoch)
	if err != nil {
		hk.log.WithError(err).Error("failed to get proposer duties for epoch")
		return
	}
	nextDuties, err := hk.beaconClient.GetProposerDuties(epoch + 1)
	if err != nil {
		hk.log.WithError(err).Error("failed to get proposer duties for next epoch")
		return
	}
	// Combine duties from current and next epoch into a single array
	duties.Data = append(duties.Data, nextDuties.Data...)

	pubkeys := [][]byte{}
	for _, duty := range duties.Data {
		pubkeys = append(pubkeys, []byte(duty.Pubkey))
	}

	registeredValidators, err := hk.mevCommitClient.GetOptInStatusForValidators(pubkeys)
	if err != nil {
		hk.log.WithError(err).Error("failed to get registered validators from mev-commit client")
		return
	}
	for i, registeredValidator := range registeredValidators {
		if registeredValidator {
			hk.redis.SetMevCommitValidatorRegistration(common.NewPubkeyHex(duties.Data[i].Pubkey))
		}
	}

	hk.log.WithField("numValidators", len(registeredValidators)).Info("updated mev-commit registered validators in Redis")
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
		err = hk.redis.SetValidatorRegistrationTimestampIfNewer(common.NewPubkeyHex(reg.Pubkey), reg.Timestamp)
		if err != nil {
			hk.log.WithError(err).Error("failed to set validator registration")
			continue
		}
	}
	hk.log.Infof("updating %d validator registrations in Redis done - %f sec", len(regs), time.Since(timeStarted).Seconds())
}
