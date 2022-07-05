// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type ProposerMemoryDatastore struct {
	registrations   map[types.PublicKey]*types.SignedValidatorRegistration
	knownValidators map[string]bool
	requestCount    map[string]int
	mu              sync.RWMutex
}

func NewProposerMemoryDatastore() *ProposerMemoryDatastore {
	return &ProposerMemoryDatastore{
		registrations:   make(map[types.PublicKey]*types.SignedValidatorRegistration),
		knownValidators: make(map[string]bool),
		requestCount:    make(map[string]int),
	}
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *ProposerMemoryDatastore) GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	ds.requestCount["GetValidatorRegistration"]++
	return ds.registrations[proposerPubkey], nil
}

func (ds *ProposerMemoryDatastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.requestCount["SaveValidatorRegistration"]++
	ds.registrations[entry.Message.Pubkey] = &entry
	return nil
}

func (ds *ProposerMemoryDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.requestCount["SaveValidatorRegistrations"]++
	for _, entry := range entries {
		ds.registrations[entry.Message.Pubkey] = &entry
	}
	return nil
}

// GetRequestCount returns the number of Request made to a method
func (ds *ProposerMemoryDatastore) GetRequestCount(method string) int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.requestCount[method]
}

func (ds *ProposerMemoryDatastore) IsKnownValidator(pubkeyHex string) (bool, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	_, ok := ds.knownValidators[pubkeyHex]
	return ok, nil
}

func (ds *ProposerMemoryDatastore) SetKnownValidator(pubkeyHex string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.knownValidators[pubkeyHex] = true
	return nil
}
