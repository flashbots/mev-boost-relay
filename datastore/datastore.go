// Package datastore helps storing data, utilizing Redis and Postgres as backends
package datastore

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/attestantio/go-builder-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/database"
	"github.com/pkg/errors"
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

	redis     *RedisCache
	memcached *Memcached
	db        database.IDatabaseService

	knownValidatorsByPubkey map[types.PubkeyHex]uint64
	knownValidatorsByIndex  map[uint64]types.PubkeyHex
	knownValidatorsLock     sync.RWMutex
}

func NewDatastore(log *logrus.Entry, redisCache *RedisCache, memcached *Memcached, db database.IDatabaseService) (ds *Datastore, err error) {
	ds = &Datastore{
		log:                     log.WithField("component", "datastore"),
		db:                      db,
		memcached:               memcached,
		redis:                   redisCache,
		knownValidatorsByPubkey: make(map[types.PubkeyHex]uint64),
		knownValidatorsByIndex:  make(map[uint64]types.PubkeyHex),
	}

	return ds, err
}

// RefreshKnownValidators loads known validators from Redis into memory
func (ds *Datastore) RefreshKnownValidators() (cnt int, err error) {
	knownValidatorsByIndex, err := ds.redis.GetKnownValidators()
	if err != nil {
		return 0, err
	}

	knownValidatorsByPubkey := make(map[types.PubkeyHex]uint64)
	for index, pubkey := range knownValidatorsByIndex {
		knownValidatorsByPubkey[pubkey] = index
	}

	ds.knownValidatorsLock.Lock()
	defer ds.knownValidatorsLock.Unlock()
	ds.knownValidatorsByPubkey = knownValidatorsByPubkey
	ds.knownValidatorsByIndex = knownValidatorsByIndex
	return len(knownValidatorsByIndex), nil
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

func (ds *Datastore) NumRegisteredValidators() (uint64, error) {
	return ds.db.NumRegisteredValidators()
}

// SaveValidatorRegistration saves a validator registration into both Redis and the database
func (ds *Datastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	// First save in the database
	err := ds.db.SaveValidatorRegistration(database.SignedValidatorRegistrationToEntry(entry))
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to database")
	}

	// then save in redis
	pk := types.NewPubkeyHex(entry.Message.Pubkey.String())
	err = ds.redis.SetValidatorRegistrationTimestampIfNewer(pk, entry.Message.Timestamp)
	if err != nil {
		return errors.Wrap(err, "failed saving validator registration to redis")
	}

	return nil
}

// GetGetPayloadResponse returns the getPayload response from memory or Redis or Database
func (ds *Datastore) GetGetPayloadResponse(slot uint64, proposerPubkey, blockHash string) (*common.VersionedExecutionPayload, error) {
	_proposerPubkey := strings.ToLower(proposerPubkey)
	_blockHash := strings.ToLower(blockHash)

	// 1. try to get from Redis
	resp, err := ds.redis.GetExecutionPayload(slot, _proposerPubkey, _blockHash)
	if err != nil {
		ds.log.WithError(err).Error("error getting execution payload from redis")
	} else {
		ds.log.Debug("getPayload response from redis")
		return resp, nil
	}

	// 2. try to get from Memcached
	if ds.memcached != nil {
		resp, err = ds.memcached.GetExecutionPayload(slot, _proposerPubkey, _blockHash)
		if err != nil {
			ds.log.WithError(err).Error("error getting execution payload from memcached")
		} else if resp != nil {
			ds.log.Debug("getPayload response from memcached")
			return resp, nil
		}
	}

	// 3. try to get from database (should not happen, it's just a backup)
	executionPayloadEntry, err := ds.db.GetExecutionPayloadEntryBySlotPkHash(slot, proposerPubkey, blockHash)
	if err != nil {
		ds.log.WithError(err).Error("error getting execution payload from database")
		return nil, err
	}

	// Got it from databaase, now deserialize execution payload and compile full response
	ds.log.Warn("getPayload response from database, primary storage failed")
	var res consensusspec.DataVersion
	err = json.Unmarshal([]byte(executionPayloadEntry.Version), &res)
	if err != nil {
		ds.log.Debug("invalid getPayload version from database")
		return nil, err
	}
	switch res {
	case consensusspec.DataVersionCapella:
		executionPayload := new(capella.ExecutionPayload)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		capella := api.VersionedExecutionPayload{
			Version:   res,
			Capella:   executionPayload,
			Bellatrix: nil,
		}
		return &common.VersionedExecutionPayload{
			Capella:   &capella,
			Bellatrix: nil,
		}, nil
	case consensusspec.DataVersionBellatrix:
		executionPayload := new(types.ExecutionPayload)
		err = json.Unmarshal([]byte(executionPayloadEntry.Payload), executionPayload)
		if err != nil {
			return nil, err
		}
		bellatrix := types.GetPayloadResponse{
			Version: types.VersionString(res.String()),
			Data:    executionPayload,
		}
		return &common.VersionedExecutionPayload{
			Bellatrix: &bellatrix,
			Capella:   nil,
		}, nil
	case consensusspec.DataVersionAltair, consensusspec.DataVersionPhase0:
		return nil, errors.New("unsupported execution payload version")
	default:
		return nil, errors.New("unknown execution payload version")
	}
}
