package datastore

import (
	"fmt"
	"strings"
	"sync"

	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
)

// ProdDatastore provides a local memory cache with a Redis and DB backend
type ProdDatastore struct {
	log   *logrus.Entry
	redis *RedisCache
	db    database.IDatabaseService

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex

	// In-memory cache of validator registrations
	// validatorRegistrations     map[types.PubkeyHex]types.SignedValidatorRegistration
	// validatorRegistrationsLock sync.RWMutex

	bidLock sync.RWMutex
	bids    map[BidKey]*types.GetHeaderResponse

	blockLock sync.RWMutex
	blocks    map[BlockKey]*BlockBidAndTrace
}

func NewProdDatastore(log *logrus.Entry, redisCache *RedisCache, db database.IDatabaseService) (ds *ProdDatastore, err error) {
	ds = &ProdDatastore{
		log:                     log.WithField("module", "datastore"),
		db:                      db,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
		bids:                    make(map[BidKey]*types.GetHeaderResponse),
		blocks:                  make(map[BlockKey]*BlockBidAndTrace),
	}

	return ds, err
}

// RefreshKnownValidators loads known validators from Redis into memory
func (ds *ProdDatastore) RefreshKnownValidators() (cnt int, err error) {
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

func (ds *ProdDatastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	_, found := ds.knownValidatorsByPubkey[pubkeyHex]
	return found
}

func (ds *ProdDatastore) GetKnownValidatorPubkeyByIndex(index uint64) (types.PubkeyHex, bool) {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	pk, found := ds.knownValidatorsByIndex[index]
	return pk, found
}

func (ds *ProdDatastore) NumKnownValidators() int {
	ds.knownValidatorsLock.RLock()
	defer ds.knownValidatorsLock.RUnlock()
	return len(ds.knownValidatorsByIndex)
}

func (ds *ProdDatastore) NumRegisteredValidators() (int64, error) {
	return ds.redis.NumRegisteredValidators()
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *ProdDatastore) GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	return ds.redis.GetValidatorRegistration(pubkeyHex)
}

func (ds *ProdDatastore) GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error) {
	return ds.redis.GetValidatorRegistrationTimestamp(pubkeyHex)
}

func (ds *ProdDatastore) SetValidatorRegistration(entry types.SignedValidatorRegistration) error {
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

func (ds *ProdDatastore) SaveBidAndBlock(slot uint64, proposerPubkey string, signedBidTrace *types.SignedBidTrace, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error {
	bidKey := BidKey{
		Slot:           slot,
		ParentHash:     strings.ToLower(headerResp.Data.Message.Header.ParentHash.String()),
		ProposerPubkey: strings.ToLower(proposerPubkey),
	}

	blockKey := BlockKey{
		Slot:           slot,
		ProposerPubkey: strings.ToLower(proposerPubkey),
		BlockHash:      strings.ToLower(headerResp.Data.Message.Header.BlockHash.String()),
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
	return nil
}

func (ds *ProdDatastore) CleanupOldBidsAndBlocks(headSlot uint64) (numRemoved int, numRemaining int) {
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

func (ds *ProdDatastore) GetBid(slot uint64, parentHash string, proposerPubkey string) (*types.GetHeaderResponse, error) {
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

func (ds *ProdDatastore) GetBlockBidAndTrace(slot uint64, proposerPubkey string, blockHash string) (*BlockBidAndTrace, error) {
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

func (ds *ProdDatastore) IncEpochSummaryVal(epoch uint64, field string, value int64) (newVal int64, err error) {
	newVal, err = ds.redis.IncEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).Error("IncEpochSummaryVal failed")
	}
	return newVal, err
}

func (ds *ProdDatastore) SetEpochSummaryVal(epoch uint64, field string, value int64) (err error) {
	err = ds.redis.SetEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).Error("SetEpochSummaryVal failed")
	}
	return err
}

func (ds *ProdDatastore) SetNXEpochSummaryVal(epoch uint64, field string, value int64) (err error) {
	err = ds.redis.SetNXEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).Error("SetNXEpochSummaryVal failed")
	}
	return err
}

func (ds *ProdDatastore) IncSlotSummaryVal(slot uint64, field string, value int64) (newVal int64, err error) {
	newVal, err = ds.redis.IncSlotSummaryVal(slot, field, value)
	if err != nil {
		ds.log.WithError(err).Error("IncSlotSummaryVal failed")
	}
	return newVal, err
}

func (ds *ProdDatastore) SetSlotSummaryVal(slot uint64, field string, value int64) (err error) {
	err = ds.redis.SetSlotSummaryVal(slot, field, value)
	if err != nil {
		ds.log.WithError(err).Error("SetSlotSummaryVal failed")
	}
	return err
}

func (ds *ProdDatastore) SetNXSlotSummaryVal(slot uint64, field string, value int64) (err error) {
	err = ds.redis.SetNXSlotSummaryVal(slot, field, value)
	if err != nil {
		ds.log.WithError(err).Error("SetNXSlotSummaryVal failed")
	}
	return err
}

func (ds *ProdDatastore) SaveDeliveredPayload(signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, bid *types.GetHeaderResponse, payload *types.GetPayloadResponse, signedBidTrace *types.SignedBidTrace) error {
	entry, err := database.NewDeliveredPayloadEntry(bid.Data, signedBlindedBeaconBlock, payload.Data, signedBidTrace)
	if err != nil {
		ds.log.WithError(err).Error("failed creating delivered-payload-entry")
		return err
	}
	err = ds.db.SaveDeliveredPayload(entry)
	if err != nil {
		ds.log.WithError(err).Error("failed saving delivered payload to database")
		return err
	}
	return nil
}

func (ds *ProdDatastore) SaveBuilderBlockSubmission(payload *types.BuilderSubmitBlockRequest) error {
	entry, err := database.NewBuilderBlockEntry(payload)
	if err != nil {
		return err
	}
	return ds.db.SaveBuilderBlockSubmission(entry)
}
