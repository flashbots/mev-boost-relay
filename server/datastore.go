package server

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type Datastore interface {
	GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error)
	SaveValidatorRegistration(entry types.SignedValidatorRegistration) error
	SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error
}

type MemoryDatastore struct {
	entries map[types.PublicKey]*types.SignedValidatorRegistration
	mu      sync.RWMutex
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *MemoryDatastore) GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.entries[proposerPubkey], nil
}

func (ds *MemoryDatastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.entries[entry.Message.Pubkey] = &entry
	return nil
}

func (ds *MemoryDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, entry := range entries {
		ds.entries[entry.Message.Pubkey] = &entry
	}
	return nil
}

func NewMemoryDatastore() Datastore {
	return &MemoryDatastore{
		entries: make(map[types.PublicKey]*types.SignedValidatorRegistration),
	}
}
