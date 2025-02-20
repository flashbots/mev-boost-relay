// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

var (
	ErrExecutionPayloadNotFound = errors.New("execution payload not found")
	ErrBidTraceNotFound         = errors.New("bidtrace not found")
)

type GetHeaderResponseKey struct {
	Slot           uint64
	ParentHash     string
	ProposerPubkey string
}

type GetPayloadResponseKey struct {
	Slot           uint64
	ProposerPubkey string
	BlockHash      string
}

// Datastore provides a local memory cache with a Redis and DB backend
type Datastore struct {
	redis     *RedisCache
	memcached *Memcached
	db        database.IDatabaseService

	knownValidatorsByPubkey   map[common.PubkeyHex]uint64
	knownValidatorsByIndex    map[uint64]common.PubkeyHex
	knownValidatorsLock       sync.RWMutex
	knownValidatorsIsUpdating uberatomic.Bool
	knownValidatorsLastSlot   uberatomic.Uint64

	// Used for proposer-API readiness check
	KnownValidatorsWasUpdated uberatomic.Bool

	// Where we can find payloads for our local auction
	// Should be protocol + hostname, e.g. http://turbo-auction-api, https://relay-builders-us.ultrasound.money
	localAuctionHost  string
	remoteAuctionHost string
	// Token used to remotely authenticate to auction API.
	auctionAuthToken string
}

func NewDatastore(redisCache *RedisCache, memcached *Memcached, db database.IDatabaseService, localAuctionHost, remoteAuctionHost, auctionAuthToken string) (ds *Datastore, err error) {
	ds = &Datastore{
		db:                      db,
		memcached:               memcached,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[common.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]common.PubkeyHex),
		localAuctionHost:        localAuctionHost,
		remoteAuctionHost:       remoteAuctionHost,
		auctionAuthToken:        auctionAuthToken,
	}

	if localAuctionHost == "" {
		log.Fatal("LOCAL_AUCTION_HOST is not set")
	}

	if remoteAuctionHost == "" {
		log.Fatal("REMOTE_AUCTION_HOST is not set")
	}

	return ds, err
}

// RefreshKnownValidators loads known validators from CL client into memory
//
// For the CL client this is an expensive operation and takes a bunch of resources.
// This is why we schedule the requests for slot 4 and 20 of every epoch, 6 seconds
// into the slot (on suggestion of @potuz). It's also run once at startup.
func (ds *Datastore) RefreshKnownValidators(log *logrus.Entry, beaconClient beaconclient.IMultiBeaconClient, slot uint64) {
	// Ensure there's only one at a time
	if isAlreadyUpdating := ds.knownValidatorsIsUpdating.Swap(true); isAlreadyUpdating {
		return
	}
	defer ds.knownValidatorsIsUpdating.Store(false)

	headSlotPos := common.SlotPos(slot) // 1-based position in epoch (32 slots, 1..32)
	lastUpdateSlot := ds.knownValidatorsLastSlot.Load()
	log = log.WithFields(logrus.Fields{
		"datastoreMethod": "RefreshKnownValidators",
		"headSlot":        slot,
		"headSlotPos":     headSlotPos,
		"lastUpdateSlot":  lastUpdateSlot,
	})

	// Only proceed if slot newer than last updated
	if slot <= lastUpdateSlot {
		return
	}

	// Minimum amount of slots between updates
	slotsSinceLastUpdate := slot - lastUpdateSlot
	if slotsSinceLastUpdate < 6 {
		return
	}

	log.Debug("RefreshKnownValidators init")

	// Proceed only if forced, or on slot-position 4 or 20
	forceUpdate := slotsSinceLastUpdate > 32
	if !forceUpdate && headSlotPos != 4 && headSlotPos != 20 {
		return
	}

	// Wait for 6s into the slot
	if lastUpdateSlot > 0 {
		time.Sleep(6 * time.Second)
	}

	ds.RefreshKnownValidatorsWithoutChecks(log, beaconClient, slot)
}

func (ds *Datastore) RefreshKnownValidatorsWithoutChecks(log *logrus.Entry, beaconClient beaconclient.IMultiBeaconClient, slot uint64) {
	log.Info("Querying validators from beacon node... (this may take a while)")
	timeStartFetching := time.Now()
	validators, err := beaconClient.GetStateValidators(beaconclient.StateIDHead) // head is fastest
	if err != nil {
		log.WithError(err).Error("failed to fetch validators from all beacon nodes")
		return
	}

	numValidators := len(validators.Data)
	log = log.WithFields(logrus.Fields{
		"numKnownValidators":        numValidators,
		"durationFetchValidatorsMs": time.Since(timeStartFetching).Milliseconds(),
	})
	log.Infof("received known validators from beacon-node")

	err = ds.redis.SetStats(RedisStatsFieldValidatorsTotal, strconv.Itoa(numValidators))
	if err != nil {
		log.WithError(err).Error("failed to set stats for RedisStatsFieldValidatorsTotal")
	}

	// At this point, consider the update successful
	ds.knownValidatorsLastSlot.Store(slot)

	knownValidatorsByPubkey := make(map[common.PubkeyHex]uint64)
	knownValidatorsByIndex := make(map[uint64]common.PubkeyHex)

	for _, valEntry := range validators.Data {
		pk := common.NewPubkeyHex(valEntry.Validator.Pubkey)
		knownValidatorsByPubkey[pk] = valEntry.Index
		knownValidatorsByIndex[valEntry.Index] = pk
	}

	ds.knownValidatorsLock.Lock()
	ds.knownValidatorsByPubkey = knownValidatorsByPubkey
	ds.knownValidatorsByIndex = knownValidatorsByIndex
	ds.knownValidatorsLock.Unlock()

	ds.KnownValidatorsWasUpdated.Store(true)
	log.Infof("known validators updated")
}

func (ds *Datastore) IsKnownValidator(pubkeyHex common.PubkeyHex) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	_, found := ds.knownValidatorsByPubkey[pubkeyHex]
	return found
}

func (ds *Datastore) GetKnownValidatorPubkeyByIndex(index uint64) (common.PubkeyHex, bool) {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	pk, found := ds.knownValidatorsByIndex[index]
	return pk, found
}

func (ds *Datastore) NumKnownValidators() int {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	return len(ds.knownValidatorsByIndex)
}

func (ds *Datastore) NumRegisteredValidators() (uint64, error) {
	return ds.db.NumRegisteredValidators()
}

func (ds *Datastore) SetKnownValidator(pubkeyHex common.PubkeyHex, index uint64) {
	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()

	ds.knownValidatorsByPubkey[pubkeyHex] = index
	ds.knownValidatorsByIndex[index] = pubkeyHex
}

// SaveValidatorRegistration saves a validator registration into both Redis and the database
func (ds *Datastore) SaveValidatorRegistration(entry builderApiV1.SignedValidatorRegistration) error {
	// First save in the database
	err := ds.db.SaveValidatorRegistration(database.SignedValidatorRegistrationToEntry(entry))
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to database")
	}

	// then save in redis
	pk := common.NewPubkeyHex(entry.Message.Pubkey.String())
	err = ds.redis.SetValidatorRegistrationTimestampIfNewer(pk, uint64(entry.Message.Timestamp.Unix())) //nolint:gosec
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to redis")
	}

	return nil
}

// RedisPayload returns the getPayload response from Redis
func (ds *Datastore) RedisPayload(log *logrus.Entry, slot uint64, proposerPubkey, blockHash string) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	log = log.WithField("datastoreMethod", "RedisPayload")
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	// try to get from Redis
	resp, err := ds.redis.GetPayloadContents(slot, _proposerPubkey, _blockHash)

	// redis.Nil is a common error when the key is not found
	// this may happen if we're asked for a payload we don't have.
	if errors.Is(err, redis.Nil) {
		log.WithError(err).Warn("execution payload not found in redis")
		return nil, ErrExecutionPayloadNotFound
	}

	if err != nil {
		log.WithError(err).Error("error getting execution payload from redis")
		return nil, err
	}

	log.Debug("getPayload response from redis")
	return resp, nil
}
