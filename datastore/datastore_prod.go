package datastore

import (
	"errors"
	"strings"
	"sync"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/boost-relay/database"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/sirupsen/logrus"
)

// ProdDatastore provides a local memory cache with a Redis and DB backend
type ProdDatastore struct {
	redis *RedisCache
	db    *database.DatabaseService
	log   *logrus.Entry

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex

	// In-memory cache of validator registrations
	// validatorRegistrations     map[types.PubkeyHex]types.SignedValidatorRegistration
	// validatorRegistrationsLock sync.RWMutex

	bidLock sync.RWMutex
	bids    map[BidKey]*types.GetHeaderResponse

	blockLock sync.RWMutex
	blocks    map[BlockKey]*types.GetPayloadResponse
}

func NewProdDatastore(log *logrus.Entry, redisCache *RedisCache, postgresDSN string) (ds *ProdDatastore, err error) {
	ds = &ProdDatastore{
		log:                     log.WithField("module", "datastore"),
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
		bids:                    make(map[BidKey]*types.GetHeaderResponse),
		blocks:                  make(map[BlockKey]*types.GetPayloadResponse),
	}

	if postgresDSN == "" {
		return nil, errors.New("no postgres DSN provided")
	}

	ds.log.Infof("Connecting to Postgres database...")
	ds.db, err = database.NewDatabaseService(postgresDSN)
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
		return err
	}

	if ds.db != nil {
		err = ds.db.SaveValidatorRegistration(entry)
	}
	return err
}

func (ds *ProdDatastore) SaveBidAndBlock(slot uint64, proposerPubkey string, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error {
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
	ds.blocks[blockKey] = payloadResp
	ds.blockLock.Unlock()
	return nil
}

func (ds *ProdDatastore) CleanupOldBidsAndBlocks(headSlot uint64) (numRemoved int, numRemaining int) {
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

func (ds *ProdDatastore) GetBlock(slot uint64, proposerPubkey string, blockHash string) (*types.GetPayloadResponse, error) {
	blockKey := BlockKey{
		Slot:           slot,
		ProposerPubkey: strings.ToLower(proposerPubkey),
		BlockHash:      strings.ToLower(blockHash),
	}

	ds.blockLock.RLock()
	block := ds.blocks[blockKey]
	ds.blockLock.RUnlock()
	return block, nil
}

func (ds *ProdDatastore) SaveEpochSummary(summary common.EpochSummary) error {
	return ds.db.SaveEpochSummary(summary)
}

func (ds *ProdDatastore) IncEpochSummaryVal(epoch uint64, field string, value int64) (newVal int64, err error) {
	newVal, err = ds.redis.IncEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).WithFields(logrus.Fields{
			"epoch": epoch,
			"field": field,
			"value": value,
		}).Error("Error incrementing epoch summary val")
	}
	return newVal, err
}

func (ds *ProdDatastore) SetEpochSummaryVal(epoch uint64, field string, value int64) (err error) {
	err = ds.redis.SetEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).WithFields(logrus.Fields{
			"epoch": epoch,
			"field": field,
			"value": value,
		}).Error("Error setting epoch summary val")
	}
	return err
}

func (ds *ProdDatastore) SetNXEpochSummaryVal(epoch uint64, field string, value int64) (err error) {
	err = ds.redis.SetNXEpochSummaryVal(epoch, field, value)
	if err != nil {
		ds.log.WithError(err).WithFields(logrus.Fields{
			"epoch": epoch,
			"field": field,
			"value": value,
		}).Error("Error setting epoch summary val")
	}
	return err
}

// func (ds *ProdDatastore) IncSlotSummaryVal(epoch uint64, key string, value any) error {

// }
