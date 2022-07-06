// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type ProposerMemoryDatastore struct {
	registrations   map[types.PubkeyHex]*types.SignedValidatorRegistration
	knownValidators map[types.PubkeyHex]bool
	mu              sync.RWMutex
}

func NewProposerMemoryDatastore() *ProposerMemoryDatastore {
	return &ProposerMemoryDatastore{
		registrations:   make(map[types.PubkeyHex]*types.SignedValidatorRegistration),
		knownValidators: make(map[types.PubkeyHex]bool),
	}
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *ProposerMemoryDatastore) GetValidatorRegistration(proposerPubkey types.PubkeyHex) (*types.SignedValidatorRegistration, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.registrations[proposerPubkey], nil
}

func (ds *ProposerMemoryDatastore) UpdateValidatorRegistration(entry types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	lastEntry, ok := ds.registrations[entry.Message.Pubkey.PubkeyHex()]
	if !ok || entry.Message.Timestamp > lastEntry.Message.Timestamp {
		ds.registrations[entry.Message.Pubkey.PubkeyHex()] = &entry
	}
	return nil
}

// func (ds *ProposerMemoryDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
// 	ds.mu.Lock()
// 	defer ds.mu.Unlock()
// 	for _, entry := range entries {
// 		ds.registrations[entry.Message.Pubkey] = &entry
// 	}
// 	return nil
// }

func (ds *ProposerMemoryDatastore) IsKnownValidator(pubkeyHex types.PubkeyHex) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.knownValidators[pubkeyHex]
}

func (ds *ProposerMemoryDatastore) RefreshKnownValidators() (cnt int, err error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return len(ds.knownValidators), nil
}

func (ds *ProposerMemoryDatastore) SetKnownValidator(pubkeyHex types.PubkeyHex) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.knownValidators[pubkeyHex] = true
	return nil
}

func (ds *ProposerMemoryDatastore) SetKnownValidators(knownValidators map[types.PubkeyHex]bool) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.knownValidators = knownValidators
	return nil
}
