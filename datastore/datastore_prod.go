package datastore

import (
	"strings"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

// ProdProposerDatastore provides a local memory cache with a Redis and DB backend
type ProdProposerDatastore struct {
	redis *RedisCache

	knownValidators     map[types.PubkeyHex]bool
	knownValidatorsLock sync.RWMutex

	bidLock sync.RWMutex
	bids    map[BidKey]*types.GetHeaderResponse

	blockLock sync.RWMutex
	blocks    map[BlockKey]*types.GetPayloadResponse
}

func NewProdProposerDatastore(redisCache *RedisCache) *ProdProposerDatastore {
	return &ProdProposerDatastore{
		redis:           redisCache,
		knownValidators: make(map[types.PubkeyHex]bool),
		bids:            make(map[BidKey]*types.GetHeaderResponse),
		blocks:          make(map[BlockKey]*types.GetPayloadResponse),
	}
}

// RefreshKnownValidators loads known validators from Redis into memory
func (ds *ProdProposerDatastore) RefreshKnownValidators() (cnt int, err error) {
	knownValidators, err := ds.redis.GetKnownValidators()
	if err != nil {
		return 0, err
	}

	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()
	ds.knownValidators = knownValidators
	return len(knownValidators), nil
}

func (ds *ProdProposerDatastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	return ds.knownValidators[pubkeyHex]
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *ProdProposerDatastore) GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	return ds.redis.GetValidatorRegistration(pubkeyHex)
}

func (ds *ProdProposerDatastore) GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error) {
	return ds.redis.GetValidatorRegistrationTimestamp(pubkeyHex)
}

func (ds *ProdProposerDatastore) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
	return ds.redis.SetValidatorRegistration(entry)
}

func (ds *ProdProposerDatastore) SaveBidAndBlock(slot uint64, proposerPubkey string, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error {
	bidKey := BidKey{
		Slot:           slot,
		ParentHash:     strings.ToLower(headerResp.Data.Message.Header.ParentHash.String()),
		ProposerPubkey: strings.ToLower(proposerPubkey),
	}

	blockKey := BlockKey{
		Slot:      slot,
		BlockHash: strings.ToLower(headerResp.Data.Message.Header.BlockHash.String()),
	}

	ds.bidLock.Lock()
	ds.bids[bidKey] = headerResp
	ds.bidLock.Unlock()

	ds.blockLock.Lock()
	ds.blocks[blockKey] = payloadResp
	ds.blockLock.Unlock()
	return nil
}

func (ds *ProdProposerDatastore) CleanupOldBidsAndBlocks(headSlot uint64) (numRemoved int, numRemaining int) {
	ds.bidLock.Lock()
	for key := range ds.bids {
		if key.Slot < headSlot-10 {
			delete(ds.bids, key)
			numRemoved++
		}
	}
	numRemaining = len(ds.bids)
	ds.bidLock.Unlock()

	ds.blockLock.Lock()
	for key := range ds.blocks {
		if key.Slot < headSlot-10 {
			delete(ds.blocks, key)
		}
	}
	ds.blockLock.Unlock()
	return
}

func (ds *ProdProposerDatastore) GetBid(slot uint64, parentHash string, proposerPubkey string) (*types.GetHeaderResponse, error) {
	bidKey := BidKey{
		Slot:           slot,
		ParentHash:     strings.ToLower(parentHash),
		ProposerPubkey: strings.ToLower(proposerPubkey),
	}

	ds.bidLock.RLock()
	bid := ds.bids[bidKey]
	ds.bidLock.RUnlock()
	return bid, nil
}

func (ds *ProdProposerDatastore) GetBlock(slot uint64, blockHash string) (*types.GetPayloadResponse, error) {
	blockKey := BlockKey{
		Slot:      slot,
		BlockHash: strings.ToLower(blockHash),
	}

	ds.blockLock.RLock()
	block := ds.blocks[blockKey]
	ds.blockLock.RUnlock()
	return block, nil
}
