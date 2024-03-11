// Package beaconclient provides a beacon-node client
package beaconclient

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

var (
	ErrBeaconNodeSyncing        = errors.New("beacon node is syncing or unavailable")
	ErrBeaconNodesUnavailable   = errors.New("all beacon nodes responded with error")
	ErrWithdrawalsBeforeCapella = errors.New("withdrawals are not supported before capella")
	ErrBeaconBlock202           = errors.New("beacon block failed validation but was still broadcast (202)")
)

type BroadcastMode string

const (
	Gossip                   BroadcastMode = "gossip"                     // lightweight gossip checks only
	Consensus                BroadcastMode = "consensus"                  // full consensus checks, including validation of all signatures and blocks fields
	ConsensusAndEquivocation BroadcastMode = "consensus_and_equivocation" // the same as `consensus`, with an extra equivocation check
)

// IMultiBeaconClient is the interface for the MultiBeaconClient, which can manage several beacon client instances under the hood
type IMultiBeaconClient interface {
	BestSyncStatus() (*SyncStatusPayloadData, error)
	SubscribeToHeadEvents(slotC chan HeadEventData)
	// SubscribeToPayloadAttributesEvents subscribes to payload attributes events to validate fields such as prevrandao and withdrawals
	SubscribeToPayloadAttributesEvents(payloadAttrC chan PayloadAttributesEvent)

	// GetStateValidators returns all active and pending validators from the beacon node
	GetStateValidators(stateID string) (*GetStateValidatorsResponse, error)
	GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
	PublishBlock(block *common.VersionedSignedProposal) (code int, err error)
	GetGenesis() (*GetGenesisResponse, error)
	GetSpec() (spec *GetSpecResponse, err error)
	GetForkSchedule() (spec *GetForkScheduleResponse, err error)
	GetRandao(slot uint64) (spec *GetRandaoResponse, err error)
	GetWithdrawals(slot uint64) (spec *GetWithdrawalsResponse, err error)
}

// IBeaconInstance is the interface for a single beacon client instance
type IBeaconInstance interface {
	SyncStatus() (*SyncStatusPayloadData, error)
	CurrentSlot() (uint64, error)
	SubscribeToHeadEvents(slotC chan HeadEventData)
	SubscribeToPayloadAttributesEvents(slotC chan PayloadAttributesEvent)
	GetStateValidators(stateID string) (*GetStateValidatorsResponse, error)
	GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
	GetURI() string
	PublishBlock(block *common.VersionedSignedProposal, broadcastMode BroadcastMode) (code int, err error)
	GetGenesis() (*GetGenesisResponse, error)
	GetSpec() (spec *GetSpecResponse, err error)
	GetForkSchedule() (spec *GetForkScheduleResponse, err error)
	GetRandao(slot uint64) (spec *GetRandaoResponse, err error)
	GetWithdrawals(slot uint64) (spec *GetWithdrawalsResponse, err error)
}

type MultiBeaconClient struct {
	log             *logrus.Entry
	bestBeaconIndex uberatomic.Int64
	beaconInstances []IBeaconInstance

	// feature flags
	ffAllowSyncingBeaconNode bool

	broadcastMode BroadcastMode
}

func NewMultiBeaconClient(log *logrus.Entry, beaconInstances []IBeaconInstance) *MultiBeaconClient {
	client := &MultiBeaconClient{
		log:                      log.WithField("component", "beaconClient"),
		beaconInstances:          beaconInstances,
		bestBeaconIndex:          *uberatomic.NewInt64(0),
		ffAllowSyncingBeaconNode: false,
		broadcastMode:            ConsensusAndEquivocation,
	}

	// feature flags
	if os.Getenv("ALLOW_SYNCING_BEACON_NODE") != "" {
		client.log.Warn("env: ALLOW_SYNCING_BEACON_NODE: allow syncing beacon node")
		client.ffAllowSyncingBeaconNode = true
	}

	broadcastModeStr := os.Getenv("BROADCAST_MODE")
	if broadcastModeStr != "" {
		broadcastMode, ok := parseBroadcastModeString(broadcastModeStr)
		if !ok {
			msg := fmt.Sprintf("env: BROADCAST_MODE: invalid value %s, leaving to default value %s", broadcastModeStr, client.broadcastMode)
			client.log.Warn(msg)
		} else {
			client.log.Info(fmt.Sprintf("env: BROADCAST_MODE: setting mode to %s", broadcastMode))
			client.broadcastMode = broadcastMode
		}
	}

	return client
}

func (c *MultiBeaconClient) BestSyncStatus() (*SyncStatusPayloadData, error) {
	var bestSyncStatus *SyncStatusPayloadData
	var foundSyncedNode bool

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

			if foundSyncedNode {
				return
			}

			if bestSyncStatus == nil {
				bestSyncStatus = syncStatus
			}

			if !syncStatus.IsSyncing {
				bestSyncStatus = syncStatus
				foundSyncedNode = true
			}
		}(instance)
	}

	// Wait for all requests to complete...
	wg.Wait()

	if !foundSyncedNode && !c.ffAllowSyncingBeaconNode {
		return nil, ErrBeaconNodeSyncing
	}

	if bestSyncStatus == nil {
		return nil, ErrBeaconNodesUnavailable
	}

	return bestSyncStatus, nil
}

// SubscribeToHeadEvents subscribes to head events from all beacon nodes. A single head event will be received multiple times,
// likely once for every beacon nodes.
func (c *MultiBeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {
	for _, instance := range c.beaconInstances {
		go instance.SubscribeToHeadEvents(slotC)
	}
}

func (c *MultiBeaconClient) SubscribeToPayloadAttributesEvents(slotC chan PayloadAttributesEvent) {
	for _, instance := range c.beaconInstances {
		go instance.SubscribeToPayloadAttributesEvents(slotC)
	}
}

// GetStateValidators returns all known validators, and queries the beacon nodes in reverse order (because it is a heavy request for the CL client)
func (c *MultiBeaconClient) GetStateValidators(stateID string) (*GetStateValidatorsResponse, error) {
	for i, client := range c.beaconInstancesByLeastUsed() {
		log := c.log.WithField("uri", client.GetURI())
		log.Debug("fetching validators")

		validators, err := client.GetStateValidators(stateID)
		if err != nil {
			log.WithError(err).Error("failed to fetch validators")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		// Received successful response. Set this index as last successful beacon node
		return validators, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

func (c *MultiBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	// return the first successful beacon node response
	clients := c.beaconInstancesByLastResponse()
	log := c.log.WithField("epoch", epoch)

	for i, client := range clients {
		log := log.WithField("uri", client.GetURI())
		log.Debug("fetching proposer duties")

		duties, err := client.GetProposerDuties(epoch)
		if err != nil {
			log.WithError(err).Error("failed to get proposer duties")
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
func (c *MultiBeaconClient) beaconInstancesByLastResponse() []IBeaconInstance {
	index := c.bestBeaconIndex.Load()
	if index == 0 {
		return c.beaconInstances
	}

	instances := make([]IBeaconInstance, len(c.beaconInstances))
	copy(instances, c.beaconInstances)
	instances[0], instances[index] = instances[index], instances[0]

	return instances
}

// beaconInstancesByLeastUsed returns a list of beacon clients that has the client
// with the last successful response as the last element of the slice (used only by
// GetStateValidators, because it's a heavy call on the CL)
func (c *MultiBeaconClient) beaconInstancesByLeastUsed() []IBeaconInstance {
	beaconInstances := c.beaconInstancesByLastResponse()
	instances := make([]IBeaconInstance, len(c.beaconInstances))
	for i := 0; i < len(beaconInstances); i++ {
		instances[i] = beaconInstances[len(beaconInstances)-i-1]
	}
	return instances
}

type publishResp struct {
	index int
	code  int
	err   error
}

// PublishBlock publishes the signed beacon block via https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/publishBlock
func (c *MultiBeaconClient) PublishBlock(block *common.VersionedSignedProposal) (code int, err error) {
	slot, err := block.Slot()
	if err != nil {
		c.log.WithError(err).Warn("failed to publish block as block slot is missing")
		return 0, err
	}
	blockHash, err := block.ExecutionBlockHash()
	if err != nil {
		c.log.WithError(err).Warn("failed to publish block as block hash is missing")
		return 0, err
	}
	log := c.log.WithFields(logrus.Fields{
		"slot":      slot,
		"blockHash": blockHash.String(),
	})

	clients := c.beaconInstancesByLastResponse()

	// The chan will be cleaner up automatically once the function exists even if it was still being written to
	resChans := make(chan publishResp, len(clients))

	for i, client := range clients {
		log := log.WithField("uri", client.GetURI())
		log.Debug("publishing block")
		go func(index int, client IBeaconInstance) {
			code, err := client.PublishBlock(block, c.broadcastMode)
			resChans <- publishResp{
				index: index,
				code:  code,
				err:   err,
			}
		}(i, client)
	}

	var lastErrPublishResp publishResp
	for i := 0; i < len(clients); i++ {
		res := <-resChans
		log = log.WithField("beacon", clients[res.index].GetURI())
		if res.err != nil {
			log.WithField("statusCode", res.code).WithError(res.err).Warn("failed to publish block")
			lastErrPublishResp = res
			continue
		} else if res.code == 202 {
			// Should the block fail full validation, a separate success response code (202) is used to indicate that the block was successfully broadcast but failed integration.
			// https://ethereum.github.io/beacon-APIs/?urls.primaryName=dev#/Beacon/publishBlock
			log.WithField("statusCode", res.code).WithError(res.err).Warn("CL client failed block integration, but block was successfully broadcast")
			lastErrPublishResp = res
			continue
		}

		c.bestBeaconIndex.Store(int64(res.index))

		log.WithField("statusCode", res.code).Info("published block")
		return res.code, nil
	}

	if lastErrPublishResp.err == nil {
		return lastErrPublishResp.code, nil
	}
	log.Error("failed to publish block on any CL node")
	return lastErrPublishResp.code, fmt.Errorf("last error: %w", lastErrPublishResp.err)
}

// GetGenesis returns the genesis info - https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis
func (c *MultiBeaconClient) GetGenesis() (genesisInfo *GetGenesisResponse, err error) {
	clients := c.beaconInstancesByLastResponse()
	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		if genesisInfo, err = client.GetGenesis(); err != nil {
			log.WithError(err).Warn("failed to get genesis info")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		return genesisInfo, nil
	}

	c.log.WithError(err).Error("failed to get genesis info on any CL node")
	return nil, err
}

// GetSpec - https://ethereum.github.io/beacon-APIs/#/Config/getSpec
func (c *MultiBeaconClient) GetSpec() (spec *GetSpecResponse, err error) {
	clients := c.beaconInstancesByLastResponse()
	for _, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		if spec, err = client.GetSpec(); err != nil {
			log.WithError(err).Warn("failed to get spec")
			continue
		}

		return spec, nil
	}

	c.log.WithError(err).Error("failed to get spec on any CL node")
	return nil, err
}

// GetForkSchedule - https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule
func (c *MultiBeaconClient) GetForkSchedule() (spec *GetForkScheduleResponse, err error) {
	clients := c.beaconInstancesByLastResponse()
	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		if spec, err = client.GetForkSchedule(); err != nil {
			log.WithError(err).Warn("failed to get fork schedule")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		return spec, nil
	}

	c.log.WithError(err).Error("failed to get fork schedule on any CL node")
	return nil, err
}

// GetRandao - 3500/eth/v1/beacon/states/<slot>/randao
func (c *MultiBeaconClient) GetRandao(slot uint64) (randaoResp *GetRandaoResponse, err error) {
	clients := c.beaconInstancesByLastResponse()
	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		if randaoResp, err = client.GetRandao(slot); err != nil {
			log.WithField("slot", slot).WithError(err).Warn("failed to get randao")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		return randaoResp, nil
	}

	c.log.WithField("slot", slot).WithError(err).Warn("failed to get randao from any CL node")
	return nil, err
}

// GetWithdrawals - 3500/eth/v1/beacon/states/<slot>/withdrawals
func (c *MultiBeaconClient) GetWithdrawals(slot uint64) (withdrawalsResp *GetWithdrawalsResponse, err error) {
	clients := c.beaconInstancesByLastResponse()
	for i, client := range clients {
		log := c.log.WithField("uri", client.GetURI())
		if withdrawalsResp, err = client.GetWithdrawals(slot); err != nil {
			if strings.Contains(err.Error(), "Withdrawals not enabled before capella") {
				break
			}
			log.WithField("slot", slot).WithError(err).Warn("failed to get withdrawals")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		return withdrawalsResp, nil
	}

	if strings.Contains(err.Error(), "Withdrawals not enabled before capella") {
		c.log.WithField("slot", slot).WithError(err).Debug("failed to get withdrawals as capella has not been reached")
		return nil, ErrWithdrawalsBeforeCapella
	}

	c.log.WithField("slot", slot).WithError(err).Warn("failed to get withdrawals from any CL node")
	return nil, err
}
