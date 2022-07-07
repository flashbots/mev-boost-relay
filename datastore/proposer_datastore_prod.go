package datastore

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/pkg/errors"
)

// ProdProposerDatastore provides a local memory cache with a Redis and DB backend
type ProdProposerDatastore struct {
	redis *RedisDatastore

	knownValidators map[types.PubkeyHex]bool
	mu              sync.RWMutex
}

func NewProdProposerDatastore(redisURI string) (*ProdProposerDatastore, error) {
	redisDs, err := NewRedisDatastore(redisURI)
	if err != nil {
		return nil, err
	}

	ds := &ProdProposerDatastore{
		redis:           redisDs,
		knownValidators: make(map[types.PubkeyHex]bool),
	}

	return ds, nil
}

// RefreshKnownValidators loads known validators from Redis into Memory
func (ds *ProdProposerDatastore) RefreshKnownValidators() (cnt int, err error) {
	knownValidators, err := ds.redis.GetKnownValidators()
	if err != nil {
		return 0, err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.knownValidators = knownValidators
	return len(knownValidators), nil
}

func (ds *ProdProposerDatastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
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

func (ds *ProdProposerDatastore) UpdateValidatorRegistration(entry types.SignedValidatorRegistration) (bool, error) {
	if entry.Message == nil {
		return false, errors.New("message is nil")
	}

	lastEntry, err := ds.redis.GetValidatorRegistration(entry.Message.Pubkey.PubkeyHex())
	if err != nil {
		return false, errors.Wrap(err, "failed to get validator registration")
	}

	if lastEntry == nil || lastEntry.Message == nil || entry.Message.Timestamp > lastEntry.Message.Timestamp {
		return true, ds.redis.SetValidatorRegistration(entry)
	}

	return false, nil
}

// func (ds *ProdProposerDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
// 	return ds.mem.SaveValidatorRegistrations(entries)
// }

// func (ds *ProdProposerDatastore) SetKnownValidator(pubkeyHex types.PubkeyHex) error {
// 	ds.knownValidators[pubkeyHex] = true
// 	return nil
// }

// func (ds *ProdProposerDatastore) SetKnownValidators(knownValidators map[types.PubkeyHex]bool) error {
// 	ds.knownValidators = knownValidators
// 	return nil
// }
