// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/sirupsen/logrus"
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
	log *logrus.Entry

	redis *RedisCache
	db    database.IDatabaseService

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex

	getHeaderResponsesLock sync.RWMutex
	getHeaderResponses     map[GetHeaderResponseKey]*types.GetHeaderResponse

	GetPayloadResponsesLock sync.RWMutex
	GetPayloadResponses     map[GetPayloadResponseKey]*types.GetPayloadResponse

	// feature flags
	ffDisableBidMemoryCache bool
	ffDisableBidRedisCache  bool
}

func NewDatastore(log *logrus.Entry, redisCache *RedisCache, db database.IDatabaseService) (ds *Datastore, err error) {
	ds = &Datastore{
		log:                     log.WithField("component", "datastore"),
		db:                      db,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
		getHeaderResponses:      make(map[GetHeaderResponseKey]*types.GetHeaderResponse),
		GetPayloadResponses:     make(map[GetPayloadResponseKey]*types.GetPayloadResponse),
	}

	if os.Getenv("DISABLE_BID_MEMORY_CACHE") == "1" {
		ds.log.Warn("env: DISABLE_BID_MEMORY_CACHE - disabling in-memory bid cache")
		ds.ffDisableBidMemoryCache = true
	}

	if os.Getenv("DISABLE_BID_REDIS_CACHE") == "1" {
		ds.log.Warn("env: DISABLE_BID_REDIS_CACHE - disabling redis bid cache")
		ds.ffDisableBidRedisCache = true
	}

	return ds, err
}

// RefreshKnownValidators loads known validators from Redis into memory
func (ds *Datastore) RefreshKnownValidators() (cnt int, err error) {
	knownValidators, err := ds.redis.GetKnownValidators()
	if err != nil {
		return 0, err
	}

	knownValidatorsByIndex := make(map[uint64]types.PubkeyHex)
	for pubkey, index := range knownValidators {
		knownValidatorsByIndex[index] = pubkey
	}

	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()
	ds.knownValidatorsByPubkey = knownValidators
	ds.knownValidatorsByIndex = knownValidatorsByIndex
	return len(knownValidators), nil
}

func (ds *Datastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	_, found := ds.knownValidatorsByPubkey[pubkeyHex]
	return found
}

func (ds *Datastore) GetKnownValidatorPubkeyByIndex(index uint64) (types.PubkeyHex, bool) {
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

func (ds *Datastore) NumRegisteredValidators() (int64, error) {
	return ds.redis.NumRegisteredValidators()
}

func (ds *Datastore) GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error) {
	return ds.redis.GetValidatorRegistrationTimestamp(pubkeyHex)
}

// SaveValidatorRegistration saves a validator registration into both Redis and the database
func (ds *Datastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	// First save in the database
	err := ds.db.SaveValidatorRegistration(database.SignedValidatorRegistrationToEntry(entry))
	if err != nil {
		ds.log.WithError(err).Error("failed to save validator registration to database")
		return err
	}

	// then save in redis
	pk := types.NewPubkeyHex(entry.Message.Pubkey.String())
	err = ds.redis.SetValidatorRegistrationTimestampIfNewer(pk, entry.Message.Timestamp)
	if err != nil {
		ds.log.WithError(err).WithField("registration", fmt.Sprintf("%+v", entry)).Error("error updating validator registration")
		return err
	}

	return nil
}

// SaveBlockSubmission stores getHeader and getPayload for later use, to memory and Redis. Note: saving to Postgres not needed, because getHeader doesn't currently check the database, getPayload finds the data it needs through a sql query.
func (ds *Datastore) SaveBlockSubmission(signedBidTrace *types.SignedBidTrace, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error {
	_blockHash := strings.ToLower(headerResp.Data.Message.Header.BlockHash.String())
	_parentHash := strings.ToLower(headerResp.Data.Message.Header.ParentHash.String())
	_proposerPubkey := strings.ToLower(signedBidTrace.Message.ProposerPubkey.String())

	// Save to memory
	if !ds.ffDisableBidMemoryCache {
		bidKey := GetHeaderResponseKey{
			Slot:           signedBidTrace.Message.Slot,
			ParentHash:     _parentHash,
			ProposerPubkey: _proposerPubkey,
		}

		blockKey := GetPayloadResponseKey{
			Slot:           signedBidTrace.Message.Slot,
			ProposerPubkey: _proposerPubkey,
			BlockHash:      _blockHash,
		}

		ds.getHeaderResponsesLock.Lock()
		ds.getHeaderResponses[bidKey] = headerResp
		ds.getHeaderResponsesLock.Unlock()

		ds.GetPayloadResponsesLock.Lock()
		ds.GetPayloadResponses[blockKey] = payloadResp
		ds.GetPayloadResponsesLock.Unlock()
	}

	// Save to Redis
	err := ds.redis.SaveGetHeaderResponse(signedBidTrace.Message.Slot, _parentHash, _proposerPubkey, headerResp)
	if err != nil {
		return err
	}

	return ds.redis.SaveGetPayloadResponse(signedBidTrace.Message.Slot, _proposerPubkey, payloadResp)
}

func (ds *Datastore) CleanupOldBidsAndBlocks(headSlot uint64) (numRemoved, numRemaining int) {
	ds.getHeaderResponsesLock.Lock()
	for key := range ds.getHeaderResponses {
		if key.Slot < headSlot-1000 {
			delete(ds.getHeaderResponses, key)
			numRemoved++
		}
	}
	numRemaining = len(ds.getHeaderResponses)
	ds.getHeaderResponsesLock.Unlock()

	ds.GetPayloadResponsesLock.Lock()
	for key := range ds.GetPayloadResponses {
		if key.Slot < headSlot-1000 {
			delete(ds.GetPayloadResponses, key)
		}
	}
	ds.GetPayloadResponsesLock.Unlock()
	return
}

// GetGetHeaderResponse returns the bid from memory or Redis
func (ds *Datastore) GetGetHeaderResponse(slot uint64, parentHash, proposerPubkey string) (*types.GetHeaderResponse, error) {
	_parentHash := strings.ToLower(parentHash)
	_proposerPubkey := strings.ToLower(proposerPubkey)

	// 1. Check in memory
	if !ds.ffDisableBidMemoryCache {
		headerKey := GetHeaderResponseKey{
			Slot:           slot,
			ParentHash:     _parentHash,
			ProposerPubkey: _proposerPubkey,
		}

		ds.getHeaderResponsesLock.RLock()
		resp, found := ds.getHeaderResponses[headerKey]
		ds.getHeaderResponsesLock.RUnlock()
		if found {
			ds.log.Debug("getHeader response from in-memory")
			return resp, nil
		}
	}

	// 2. Check in Redis
	resp, err := ds.redis.GetGetHeaderResponse(slot, _parentHash, _proposerPubkey)
	if err != nil {
		return nil, err
	}

	ds.log.Debug("getHeader response from redis")
	return resp, nil
}

// GetGetPayloadResponse returns the getPayload response from memory or Redis or Database
func (ds *Datastore) GetGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) (*types.GetPayloadResponse, error) {
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	// 1. try to get from memory
	if !ds.ffDisableBidMemoryCache {
		bidKey := GetPayloadResponseKey{
			Slot:           slot,
			ProposerPubkey: _proposerPubkey,
			BlockHash:      _blockHash,
		}

		ds.getHeaderResponsesLock.RLock()
		resp, found := ds.GetPayloadResponses[bidKey]
		ds.getHeaderResponsesLock.RUnlock()
		if found {
			ds.log.Debug("getPayload response from in-memory")
			return resp, nil
		}
	}

	// 2. try to get from Redis
	if !ds.ffDisableBidRedisCache {
		resp, err := ds.redis.GetGetPayloadResponse(slot, _proposerPubkey, _blockHash)
		if err == nil {
			ds.log.Debug("getPayload response from redis")
			return resp, nil
		}
	}

	// 3. try to get from database
	blockSubEntry, err := ds.db.GetExecutionPayloadEntryBySlotPkHash(slot, proposerPubkey, blockHash)
	if err != nil {
		return nil, err
	}

	// deserialize execution payload
	executionPayload := new(types.ExecutionPayload)
	err = json.Unmarshal([]byte(blockSubEntry.Payload), executionPayload)
	if err != nil {
		return nil, err
	}

	ds.log.Debug("getPayload response from database")
	return &types.GetPayloadResponse{
		Version: types.VersionString(blockSubEntry.Version),
		Data:    executionPayload,
	}, nil
}
