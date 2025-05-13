// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"database/sql"
	"strconv"
	"strings"
	"sync"
	"time"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiV1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/bradfitz/gomemcache/memcache"
	"github.com/flashbots/mev-boost-relay/beaconclient"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

var ErrExecutionPayloadNotFound = errors.New("execution payload not found")

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

	knownValidatorsByPubkey   map[string]uint64
	knownValidatorsByIndex    map[uint64]string
	knownValidatorsLock       sync.RWMutex
	knownValidatorsIsUpdating uberatomic.Bool
	knownValidatorsLastSlot   uberatomic.Uint64

	validatorRegistrations       map[string]builderApiV1.ValidatorRegistration
	validatorRegistrationsSimple map[string]common.SimpleValidatorRegistration
	validatorRegistrationLock    sync.RWMutex

	// Used for proposer-API readiness check
	KnownValidatorsWasUpdated uberatomic.Bool
}

func NewDatastore(redisCache *RedisCache, memcached *Memcached, db database.IDatabaseService) (ds *Datastore, err error) {
	ds = &Datastore{
		db:                           db,
		memcached:                    memcached,
		redis:                        redisCache,
		validatorRegistrations:       make(map[string]builderApiV1.ValidatorRegistration),
		validatorRegistrationsSimple: make(map[string]common.SimpleValidatorRegistration),
		knownValidatorsByPubkey:      make(map[string]uint64),
		knownValidatorsByIndex:       make(map[uint64]string),
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

	knownValidatorsByPubkey := make(map[string]uint64)
	knownValidatorsByIndex := make(map[uint64]string)

	for _, valEntry := range validators.Data {
		pk := strings.ToLower(valEntry.Validator.Pubkey)
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

func (ds *Datastore) IsKnownValidator(pubkeyHex string) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	_, found := ds.knownValidatorsByPubkey[pubkeyHex]
	return found
}

func (ds *Datastore) GetKnownValidatorPubkeyByIndex(index uint64) (string, bool) {
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

func (ds *Datastore) SetKnownValidator(pubkeyHex string, index uint64) {
	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()

	ds.knownValidatorsByPubkey[pubkeyHex] = index
	ds.knownValidatorsByIndex[index] = pubkeyHex
}

// GetCachedValidatorRegistration returns a validator registration from local cache or Redis
// If not found, it returns (nil, nil)
func (ds *Datastore) GetCachedValidatorRegistration(proposerPubkey string) (*builderApiV1.ValidatorRegistration, *common.SimpleValidatorRegistration, error) {
	var err error

	// acquire read lock and read
	ds.validatorRegistrationLock.RLock()
	cachedRegistration, cachedRegistrationFound := ds.validatorRegistrations[proposerPubkey]
	cachedSimpleRegistration, cachedSimpleRegistrationFound := ds.validatorRegistrationsSimple[proposerPubkey]
	ds.validatorRegistrationLock.RUnlock()

	if cachedRegistrationFound && cachedSimpleRegistrationFound {
		return &cachedRegistration, &cachedSimpleRegistration, nil
	}

	// if not, try to get it from Redis
	cachedRegistrationData, err := ds.redis.GetValidatorRegistrationData(proposerPubkey)
	if err == nil && cachedRegistrationData != nil {
		// save in local cache
		ds.saveValidatorRegistrationInLocalCache(cachedRegistrationData)
	}
	return cachedRegistrationData, nil, err
}

// saveValidatorRegistrationInLocalCache stores a validator registration in local cache in two formats
func (ds *Datastore) saveValidatorRegistrationInLocalCache(entry *builderApiV1.ValidatorRegistration) {
	simpleReg := common.ValidatorRegistrationToSimpleValidatorRegistration(entry)

	ds.validatorRegistrationLock.Lock()
	ds.validatorRegistrations[entry.Pubkey.String()] = *entry
	ds.validatorRegistrationsSimple[simpleReg.Pubkey] = *simpleReg
	ds.validatorRegistrationLock.Unlock()
}

// SaveValidatorRegistration saves a validator registration into local cache, Redis and the database
// Note that this function is called synchronously, so no need to lock the cache
func (ds *Datastore) SaveValidatorRegistration(entry *builderApiV1.SignedValidatorRegistration) error {
	// Save in local cache
	ds.saveValidatorRegistrationInLocalCache(entry.Message)

	// Save in the database
	err := ds.db.SaveValidatorRegistration(database.SignedValidatorRegistrationToEntry(*entry))
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to database")
	}

	// Save in Redis
	err = ds.redis.SetValidatorRegistrationData(entry.Message)
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to redis")
	}

	return nil
}

// GetGetPayloadResponse returns the getPayload response from memory or Redis or Database
func (ds *Datastore) GetGetPayloadResponse(log *logrus.Entry, slot uint64, proposerPubkey, blockHash string) (*builderApi.VersionedSubmitBlindedBlockResponse, error) {
	log = log.WithField("datastoreMethod", "GetGetPayloadResponse")
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	// 1. try to get from Redis
	resp, err := ds.redis.GetPayloadContents(slot, _proposerPubkey, _blockHash)
	if errors.Is(err, redis.Nil) {
		log.WithError(err).Warn("execution payload not found in redis")
	} else if err != nil {
		log.WithError(err).Error("error getting execution payload from redis")
	} else {
		log.Debug("getPayload response from redis")
		return resp, nil
	}

	// 2. try to get from Memcached
	if ds.memcached != nil {
		resp, err = ds.memcached.GetExecutionPayload(slot, _proposerPubkey, _blockHash)
		if errors.Is(err, memcache.ErrCacheMiss) {
			log.WithError(err).Warn("execution payload not found in memcached")
		} else if err != nil {
			log.WithError(err).Error("error getting execution payload from memcached")
		} else if resp != nil {
			log.Debug("getPayload response from memcached")
			return resp, nil
		}
	}

	// 3. try to get from database (should not happen, it's just a backup)
	executionPayloadEntry, err := ds.db.GetExecutionPayloadEntryBySlotPkHash(slot, proposerPubkey, blockHash)
	if errors.Is(err, sql.ErrNoRows) {
		log.WithError(err).Warn("execution payload not found in database")
		return nil, ErrExecutionPayloadNotFound
	} else if err != nil {
		log.WithError(err).Error("error getting execution payload from database")
		return nil, err
	}

	// Got it from database, now deserialize execution payload and compile full response
	log.Warn("getPayload response from database, primary storage failed")
	return database.ExecutionPayloadEntryToExecutionPayload(executionPayloadEntry)
}
