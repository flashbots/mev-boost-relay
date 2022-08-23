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
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/datastore"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

type HousekeeperOpts struct {
	Log           *logrus.Entry
	Redis         *datastore.RedisCache
	Datastore     *datastore.Datastore
	BeaconClients []beaconclient.BeaconNodeClient
}

type Housekeeper struct {
	opts *HousekeeperOpts
	log  *logrus.Entry

	datastore     *datastore.Datastore
	redis         *datastore.RedisCache
	beaconClients []beaconclient.BeaconNodeClient

	isStarted                uberatomic.Bool
	isUpdatingProposerDuties uberatomic.Bool
	proposerDutiesSlot       uint64

	headSlot uint64

	lastHealthlyBeaconNodeIndex int

	// feature flags
	ffAllowSyncingBeaconNode bool
}

var (
	ErrServerAlreadyStarted   = errors.New("server was already started")
	ErrBeaconNodeSyncing      = errors.New("beacon node is syncing")
	ErrBeaconNodesUnavailable = errors.New("all beacon nodes responded with error")
)

func NewHousekeeper(opts *HousekeeperOpts) *Housekeeper {
	server := &Housekeeper{
		opts:          opts,
		log:           opts.Log.WithField("module", "housekeeper"),
		redis:         opts.Redis,
		datastore:     opts.Datastore,
		beaconClients: opts.BeaconClients,
	}

	if os.Getenv("ALLOW_SYNCING_BEACON_NODE") != "" {
		server.log.Warn("env: ALLOW_SYNCING_BEACON_NODE: allow syncing beacon node")
		server.ffAllowSyncingBeaconNode = true
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
	bestSyncStatus, err := hk.getBestSyncStatus()
	if err != nil {
		return err
	}

	// Start regular known validator updates
	go func() {
		for {
			hk.updateKnownValidators()
			time.Sleep(common.DurationPerEpoch / 2)
		}
	}()

	// Process the current slot
	headSlot := bestSyncStatus.HeadSlot
	hk.processNewSlot(headSlot)

	// Start regular slot updates
	c := make(chan beaconclient.HeadEventData)
	for _, client := range hk.beaconClients {
		go client.SubscribeToHeadEvents(c)
	}
	for {
		headEvent := <-c
		hk.processNewSlot(headEvent.Slot)
	}
}

func (hk *Housekeeper) getBestSyncStatus() (*beaconclient.SyncStatusPayloadData, error) {
	var bestSyncStatus *beaconclient.SyncStatusPayloadData
	var numSyncedNodes uint32
	requestCtx, requestCtxCancel := context.WithCancel(context.Background())
	defer requestCtxCancel()

	// Check each beacon-node sync status
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, client := range hk.beaconClients {
		wg.Add(1)
		go func(client beaconclient.BeaconNodeClient) {
			defer wg.Done()
			log := hk.log.WithField("uri", client.GetURI())
			log.Debug("getting sync status")

			syncStatus, err := client.SyncStatus()
			if err != nil {
				log.WithError(err).Error("failed to get sync status")
				return
			}

			mu.Lock()
			defer mu.Unlock()

			if requestCtx.Err() != nil { // request has been cancelled (or deadline exceeded)
				return
			}

			if bestSyncStatus == nil {
				bestSyncStatus = syncStatus
			}

			if !syncStatus.IsSyncing {
				bestSyncStatus = syncStatus
				atomic.AddUint32(&numSyncedNodes, 1)
				requestCtxCancel()
			}
		}(client)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if numSyncedNodes == 0 && !hk.ffAllowSyncingBeaconNode {
		return nil, ErrBeaconNodeSyncing
	}

	if bestSyncStatus == nil {
		return nil, ErrBeaconNodesUnavailable
	}

	return bestSyncStatus, nil
}

func (hk *Housekeeper) processNewSlot(headSlot uint64) {
	if headSlot <= hk.headSlot {
		return
	}

	log := hk.log.WithFields(logrus.Fields{
		"headSlot":     headSlot,
		"prevHeadSlot": hk.headSlot,
	})
	if hk.headSlot > 0 {
		for s := hk.headSlot + 1; s < headSlot; s++ {
			log.WithField("slot", s).Warn("missed slot")
		}
	}

	// Update proposer duties
	go hk.updateProposerDuties(headSlot)
	go func() {
		err := hk.redis.SetStats(datastore.RedisStatsFieldLatestSlot, headSlot)
		if err != nil {
			log.WithError(err).Error("failed to set stats")
		}
	}()

	hk.headSlot = headSlot
	currentEpoch := headSlot / uint64(common.SlotsPerEpoch)
	log.WithFields(logrus.Fields{
		"epoch":              currentEpoch,
		"slotStartNextEpoch": (currentEpoch + 1) * uint64(common.SlotsPerEpoch),
	}).Infof("updated headSlot")
}

func (hk *Housekeeper) updateKnownValidators() {
	// Query beacon node for known validators
	hk.log.Debug("Querying validators from beacon node... (this may take a while)")

	validators, err := hk.fetchValidators()
	if err != nil {
		hk.log.WithError(err).Fatal("failed to fetch validators from all beacon nodes")
		return
	}

	log := hk.log.WithField("numKnownValidators", len(validators))
	log.Infof("received validators from BN")
	go func() {
		err := hk.redis.SetStats("validators_known_total", fmt.Sprint(len(validators)))
		if err != nil {
			log.WithError(err).WithField(
				"field", "validators_known_total",
			).Error("failed to set status")
		}
	}()

	// Update Redis with validators
	log.Debug("Writing to Redis...")

	for _, v := range validators {
		pubkey := types.PubkeyHex(v.Validator.Pubkey)
		err := hk.redis.SetKnownValidator(pubkey, v.Index)
		if err != nil {
			log.WithError(err).WithField("pubkey", pubkey).Fatal("failed to set known validator in Redis")
		}
	}
}

func (hk *Housekeeper) fetchValidators() (map[types.PubkeyHex]beaconclient.ValidatorResponseEntry, error) {
	// return the first successful beacon node response
	clients := hk.getBeaconClientsByLastResponse()

	var mu sync.Mutex
	for i, client := range clients {
		log := hk.log.WithField("uri", client.GetURI())
		log.Debug("fetching validators")

		mu.Lock()
		headSlot := hk.headSlot
		mu.Unlock()

		validators, err := client.FetchValidators(headSlot)
		if err != nil {
			hk.log.WithError(err).Error("failed to fetch validators")
			continue
		}

		mu.Lock()
		hk.lastHealthlyBeaconNodeIndex = i
		mu.Unlock()

		// Received successful response. Set this index as last successful beacon node
		return validators, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

func (hk *Housekeeper) updateProposerDuties(headSlot uint64) {
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
	r, err := hk.getProposerDuties(epoch)
	if err != nil {
		log.WithError(err).Fatal("failed to get proposer duties for all beacon nodes")
		return
	}

	entries := r.Data

	// Query next epoch
	r2, err := hk.getProposerDuties(epoch + 1)
	if r2 != nil {
		entries = append(entries, r2.Data...)
	} else {
		log.WithError(err).Error("failed to get proposer duties for next epoch for all beacon nodes")
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
			log.WithError(res.err).Fatal("error in loading validator registration from redis")
		} else if res.val.Entry != nil { // only if a known registration
			proposerDuties = append(proposerDuties, res.val)
		}
	}

	// Save duties to Redis
	err = hk.redis.SetProposerDuties(proposerDuties)
	if err != nil {
		log.WithError(err).Fatal("failed to set proposer duties")
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

func (hk *Housekeeper) getProposerDuties(epoch uint64) (*beaconclient.ProposerDutiesResponse, error) {
	// return the first successful beacon node response
	clients := hk.getBeaconClientsByLastResponse()

	var mu sync.Mutex
	for i, client := range clients {
		log := hk.log.WithField("uri", client.GetURI())
		log.Debug("fetching proposer duties")

		duties, err := client.GetProposerDuties(epoch)
		if err != nil {
			hk.log.WithError(err).Error("failed to get proposer duties")
			continue
		}

		mu.Lock()
		hk.lastHealthlyBeaconNodeIndex = i
		mu.Unlock()

		// Received successful response. Set this index as last successful beacon node and break
		return duties, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

// getBeaconClientsByLastResponse returns a list of beacon clients that has the client
// with the last successful response as the first element of the slice
func (hk *Housekeeper) getBeaconClientsByLastResponse() []beaconclient.BeaconNodeClient {
	var mu sync.Mutex
	mu.Lock()
	index := hk.lastHealthlyBeaconNodeIndex
	mu.Unlock()
	if index == 0 {
		return hk.beaconClients
	}

	clients := make([]beaconclient.BeaconNodeClient, len(hk.beaconClients))
	copy(clients, hk.beaconClients)
	clients[0], clients[index] = clients[index], clients[0]

	return clients
}
