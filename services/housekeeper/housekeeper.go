// Package housekeeper contains the service doing all required regular tasks
//
// - Update known validators
// - Updating proposer duties
// - Saving metrics
// - Deleting old bids
// - ...
package housekeeper

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/log"
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

	isUpdatingProposerDuties uberatomic.Bool
	proposerDutiesSlot       uint64

	headSlot uint64
}

func NewHousekeeper(opts *HousekeeperOpts) *Housekeeper {
	server := &Housekeeper{
		opts:         opts,
		log:          opts.Log.WithField("module", "housekeeper"),
		redis:        opts.Redis,
		datastore:    opts.Datastore,
		beaconClient: opts.BeaconClient,
	}

	return server
}

// Start starts the housekeeper service, blocking
func (hk *Housekeeper) Start(ctx context.Context) (err error) {
	// Check beacon-node sync status, process current slot and start slot updates
	syncStatus, err := hk.beaconClient.SyncStatus(ctx)
	if err != nil {
		return err
	}
	if syncStatus.IsSyncing {
		return errors.New("beacon node is syncing")
	}

	// Start regular known validator updates
	go func() {
		for {
			select {
			case <-time.After(common.DurationPerEpoch / 2):
				hk.updateKnownValidators(ctx)
			case <-ctx.Done():
				log.Warn("updateKnownValidators is cancelled")
				return
			}
		}
	}()

	// Process the current slot
	currentHeadSlot := syncStatus.HeadSlot
	hk.processNewSlot(ctx, currentHeadSlot)

	// Start regular slot updates
	c := make(chan uint64)
	go hk.beaconClient.SubscribeToHeadEvents(ctx, c)
	for headSlot := range c {
		hk.processNewSlot(ctx, headSlot)
	}
	return nil
}

func (hk *Housekeeper) processNewSlot(ctx context.Context, headSlot uint64) {
	if headSlot <= hk.headSlot {
		return
	}

	if hk.headSlot > 0 {
		for s := hk.headSlot + 1; s < headSlot; s++ {
			hk.log.WithField("missedSlot", s).Warnf("missed slot: %d", s)
		}
	}

	// Update proposer duties
	go hk.updateProposerDuties(ctx, headSlot)

	hk.headSlot = headSlot
	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)
	hk.log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotHead":           headSlot,
		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot to %d", headSlot)
}

func (hk *Housekeeper) updateKnownValidators(ctx context.Context) {
	// Query beacon node for known validators
	hk.log.Debug("Querying validators from beacon node... (this may take a while)")
	validators, err := hk.beaconClient.FetchValidators(ctx)
	if err != nil {
		hk.log.WithError(err).Fatal("failed to fetch validators from beacon node")
		return
	}

	hk.log.WithField("numKnownValidators", len(validators)).Infof("updateKnownValidators: received %d validators from BN", len(validators))
	go hk.redis.SetStats(context.Background(), "validators_known_total", fmt.Sprint(len(validators)))

	// Update Redis with validators
	hk.log.Debug("Writing to Redis...")

	// var last beaconclient.ValidatorResponseEntry
	for _, v := range validators {
		// last = v
		err = hk.redis.SetKnownValidator(context.Background(), types.PubkeyHex(v.Validator.Pubkey), v.Index)
		if err != nil {
			hk.log.WithError(err).WithField("pubkey", v.Validator.Pubkey).Fatal("failed to set known validator in Redis")
		}
	}

	// hk.log.Info("Updated Redis ", last.Index, " ", last.Validator.Pubkey)
}

func (hk *Housekeeper) updateProposerDuties(ctx context.Context, headSlot uint64) {
	// Should only happen once at a time
	if hk.isUpdatingProposerDuties.Swap(true) {
		return
	}
	defer hk.isUpdatingProposerDuties.Store(false)

	if headSlot%uint64(common.SlotsPerEpoch/2) != 0 && headSlot-hk.proposerDutiesSlot < uint64(common.SlotsPerEpoch/2) {
		return
	}

	epoch := headSlot / uint64(common.SlotsPerEpoch)

	log := hk.log.WithFields(logrus.Fields{
		"epochFrom": epoch,
		"epochTo":   epoch + 1,
	})
	log.Debug("updating proposer duties...")

	// Query current epoch
	r, err := hk.beaconClient.GetProposerDuties(ctx, epoch)
	if err != nil {
		log.WithError(err).Fatal("failed to get proposer duties")
		return
	}

	entries := r.Data

	// Query next epoch
	r2, err := hk.beaconClient.GetProposerDuties(ctx, epoch+1)
	if err == nil {
		entries = append(entries, r2.Data...)
	} else {
		hk.log.WithError(err).Error("failed to get proposer duties for next epoch")
	}

	// Validator registrations are queried in parallel, and this is the result struct
	type result struct {
		val types.BuilderGetValidatorsResponseEntry
		err error
	}

	// Scatter requests to Redis to get validator registrations
	c := make(chan result, len(entries))
	for i := 0; i < cap(c); i++ {
		go func(duty beaconclient.ProposerDutiesResponseData) {
			reg, err := hk.datastore.GetValidatorRegistration(ctx, types.NewPubkeyHex(duty.Pubkey))
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
			log.WithError(err).Error("error in loading validator registration from redis")
		} else if res.val.Entry != nil { // only if a known registration
			proposerDuties = append(proposerDuties, res.val)
		}
	}

	// Save duties to Redis
	hk.redis.SetProposerDuties(ctx, proposerDuties)
	hk.proposerDutiesSlot = headSlot

	// Pretty-print
	_duties := make([]string, len(proposerDuties))
	for i, duty := range proposerDuties {
		_duties[i] = fmt.Sprint(duty.Slot)
	}
	sort.Strings(_duties)
	log.WithField("numDuties", len(_duties)).Infof("proposer duties updated: %s", strings.Join(_duties, ", "))
}
