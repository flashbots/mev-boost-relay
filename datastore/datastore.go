// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/sirupsen/logrus"
)

type BidKey struct {
	Slot           uint64
	ParentHash     string
	ProposerPubkey string
}

type BlockKey struct {
	Slot           uint64
	ProposerPubkey string
	BlockHash      string
}

type BlockBidAndTrace struct {
	Trace   *types.SignedBidTrace
	Bid     *types.GetHeaderResponse
	Payload *types.GetPayloadResponse
}

// Datastore provides a local memory cache with a Redis and DB backend
type Datastore struct {
	log *logrus.Entry

	redis *RedisCache
	db    database.IDatabaseService

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex

	bidLock sync.RWMutex
	bids    map[BidKey]*types.GetHeaderResponse

	blockLock sync.RWMutex
	blocks    map[BlockKey]*BlockBidAndTrace

	// feature flags
	ffDisableBidMemoryCache bool
}

func NewDatastore(log *logrus.Entry, redisCache *RedisCache, db database.IDatabaseService) (ds *Datastore, err error) {
	ds = &Datastore{
		log:                     log.WithField("module", "datastore"),
		db:                      db,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
		bids:                    make(map[BidKey]*types.GetHeaderResponse),
		blocks:                  make(map[BlockKey]*BlockBidAndTrace),
	}

	if os.Getenv("DISABLE_BID_MEMORY_CACHE") == "1" {
		ds.log.Warn("env: DISABLE_BID_MEMORY_CACHE - disabling memory bid cache, forcing to load from Redis")
		ds.ffDisableBidMemoryCache = true
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

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *Datastore) GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	return ds.redis.GetValidatorRegistration(pubkeyHex)
}

func (ds *Datastore) GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error) {
	return ds.redis.GetValidatorRegistrationTimestamp(pubkeyHex)
}

// SetValidatorRegistration saves a validator registration into both Redis and the database
func (ds *Datastore) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	err := ds.redis.SetValidatorRegistration(entry)
	if err != nil {
		ds.log.WithError(err).WithField("registration", fmt.Sprintf("%+v", entry)).Error("error updating validator registration")
		return err
	}

	err = ds.db.SaveValidatorRegistration(entry)
	if err != nil {
		ds.log.WithError(err).Error("failed to save validator registration to database")
		return err
	}

	return nil
}

// SaveBidAndBlock stores bid, block and trace for later use. Save to memory, redis AND database
func (ds *Datastore) SaveBidAndBlock(slot uint64, proposerPubkey string, signedBidTrace *types.SignedBidTrace, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error {
	_blockHash := strings.ToLower(headerResp.Data.Message.Header.BlockHash.String())
	_parentHash := strings.ToLower(headerResp.Data.Message.Header.ParentHash.String())
	_proposerPubkey := strings.ToLower(proposerPubkey)

	bidKey := BidKey{
		Slot:           slot,
		ParentHash:     _parentHash,
		ProposerPubkey: _proposerPubkey,
	}

	blockKey := BlockKey{
		Slot:           slot,
		ProposerPubkey: _proposerPubkey,
		BlockHash:      _blockHash,
	}

	ds.bidLock.Lock()
	ds.bids[bidKey] = headerResp
	ds.bidLock.Unlock()

	ds.blockLock.Lock()
	ds.blocks[blockKey] = &BlockBidAndTrace{
		Trace:   signedBidTrace,
		Bid:     headerResp,
		Payload: payloadResp,
	}
	ds.blockLock.Unlock()

	// Save to Redis
	return ds.redis.SaveBid(slot, _parentHash, _proposerPubkey, headerResp)
}

func (ds *Datastore) CleanupOldBidsAndBlocks(headSlot uint64) (numRemoved, numRemaining int) {
	ds.bidLock.Lock()
	for key := range ds.bids {
		if key.Slot < headSlot-1000 {
			delete(ds.bids, key)
			numRemoved++
		}
	}
	numRemaining = len(ds.bids)
	ds.bidLock.Unlock()

	ds.blockLock.Lock()
	for key := range ds.blocks {
		if key.Slot < headSlot-1000 {
			delete(ds.blocks, key)
		}
	}
	ds.blockLock.Unlock()
	return
}

// GetBid returns the bid from memory or Redis
func (ds *Datastore) GetBid(slot uint64, parentHash, proposerPubkey string) (bid *types.GetHeaderResponse, err error) {
	_parentHash := strings.ToLower(parentHash)
	_proposerPubkey := strings.ToLower(proposerPubkey)

	bidKey := BidKey{
		Slot:           slot,
		ParentHash:     _parentHash,
		ProposerPubkey: _proposerPubkey,
	}

	// 1. Check in memory
	if !ds.ffDisableBidMemoryCache {
		found := false
		ds.bidLock.RLock()
		bid, found = ds.bids[bidKey]
		ds.bidLock.RUnlock()
		if found {
			return bid, nil
		}
	}

	// 2. Check in Redis
	return ds.redis.GetBid(slot, _parentHash, _proposerPubkey)
}

func (ds *Datastore) GetBlockBidAndTrace(slot uint64, proposerPubkey, blockHash string) (*BlockBidAndTrace, error) {
	blockKey := BlockKey{
		Slot:           slot,
		ProposerPubkey: strings.ToLower(proposerPubkey),
		BlockHash:      strings.ToLower(blockHash),
	}

	ds.blockLock.RLock()
	blockBidAndTrace := ds.blocks[blockKey]
	ds.blockLock.RUnlock()
	return blockBidAndTrace, nil
}

// func (ds *Datastore) SaveDeliveredPayload(signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, bid *types.GetHeaderResponse, payload *types.GetPayloadResponse, signedBidTrace *types.SignedBidTrace) error {
// 	entry, err := database.NewDeliveredPayloadEntry(bid.Data, signedBlindedBeaconBlock, payload.Data, signedBidTrace)
// 	if err != nil {
// 		ds.log.WithError(err).Error("failed creating delivered-payload-entry")
// 		return err
// 	}
// 	err = ds.db.SaveDeliveredPayload(entry)
// 	if err != nil {
// 		ds.log.WithError(err).Error("failed saving delivered payload to database")
// 		return err
// 	}
// 	return nil
// }
