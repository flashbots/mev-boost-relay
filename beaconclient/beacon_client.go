// Package beaconclient provides a beacon-node client
package beaconclient

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

var (
	ErrBeaconNodeSyncing      = errors.New("beacon node is syncing")
	ErrBeaconNodesUnavailable = errors.New("all beacon nodes responded with error")
)

type IBeaconClient interface {
	BestSyncStatus() (*SyncStatusPayloadData, error)
	SubscribeToHeadEvents(slotC chan HeadEventData)
	FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error)
	GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
}

type IBeaconInstance interface {
	SyncStatus() (*SyncStatusPayloadData, error)
	CurrentSlot() (uint64, error)
	SubscribeToHeadEvents(slotC chan HeadEventData)
	FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error)
	GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
	GetURI() string
}

type BeaconClient struct {
	log             *logrus.Entry
	bestBeaconIndex uberatomic.Int64
	beaconInstances []IBeaconInstance

	// feature flags
	ffAllowSyncingBeaconNode bool
}

func NewBeaconClient(log *logrus.Entry, beaconInstances []IBeaconInstance) *BeaconClient {
	_log := log.WithField("module", "beaconClient")

	// feature flags
	var ffAllowSyncingBeaconNode bool
	if os.Getenv("ALLOW_SYNCING_BEACON_NODE") != "" {
		log.Warn("env: ALLOW_SYNCING_BEACON_NODE: allow syncing beacon node")
		ffAllowSyncingBeaconNode = true
	}

	return &BeaconClient{
		log:                      _log,
		beaconInstances:          beaconInstances,
		bestBeaconIndex:          *uberatomic.NewInt64(0),
		ffAllowSyncingBeaconNode: ffAllowSyncingBeaconNode,
	}
}

func (c *BeaconClient) BestSyncStatus() (*SyncStatusPayloadData, error) {
	var bestSyncStatus *SyncStatusPayloadData
	var numSyncedNodes uint32
	requestCtx, requestCtxCancel := context.WithCancel(context.Background())
	defer requestCtxCancel()

	// Check each beacon-node sync status
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, instance := range c.beaconInstances {
		wg.Add(1)
		go func(instance IBeaconInstance) {
			defer wg.Done()
			log := c.log.WithField("uri", instance.GetURI())
			log.Debug("getting sync status")

			syncStatus, err := instance.SyncStatus()
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
				numSyncedNodes++
				requestCtxCancel()
			}
		}(instance)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if numSyncedNodes == 0 && !c.ffAllowSyncingBeaconNode {
		return nil, ErrBeaconNodeSyncing
	}

	if bestSyncStatus == nil {
		return nil, ErrBeaconNodesUnavailable
	}

	return bestSyncStatus, nil
}

func (c *BeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {
	for _, instance := range c.beaconInstances {
		go instance.SubscribeToHeadEvents(slotC)
	}
}

func (c *BeaconClient) FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	// return the first successful beacon node response
	clients := c.beaconInstancesByLastResponse()

	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		log.Debug("fetching validators")

		validators, err := client.FetchValidators(headSlot)
		if err != nil {
			c.log.WithError(err).Error("failed to fetch validators")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		// Received successful response. Set this index as last successful beacon node
		return validators, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

func (c *BeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	// return the first successful beacon node response
	clients := c.beaconInstancesByLastResponse()

	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		log.Debug("fetching proposer duties")

		duties, err := client.GetProposerDuties(epoch)
		if err != nil {
			c.log.WithError(err).Error("failed to get proposer duties")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		// Received successful response. Set this index as last successful beacon node
		return duties, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

// beaconInstancesByLastResponse returns a list of beacon clients that has the client
// with the last successful response as the first element of the slice
func (c *BeaconClient) beaconInstancesByLastResponse() []IBeaconInstance {
	index := c.bestBeaconIndex.Load()
	if index == 0 {
		return c.beaconInstances
	}

	instances := make([]IBeaconInstance, len(c.beaconInstances))
	copy(instances, c.beaconInstances)
	instances[0], instances[index] = instances[index], instances[0]

	return instances
}
