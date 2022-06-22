package server

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type Datastore interface {
	GetValidatorRegistration(proposerPubkey types.PublicKey) *types.SignedValidatorRegistration
	SaveValidatorRegistration(entry types.SignedValidatorRegistration)
	SaveValidatorRegistrations(entries []types.SignedValidatorRegistration)
}

type MemoryDatastore struct {
	entries map[types.PublicKey]*types.SignedValidatorRegistration
	mu      sync.RWMutex
}

func (ds *MemoryDatastore) GetValidatorRegistration(proposerPubkey types.PublicKey) *types.SignedValidatorRegistration {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return ds.entries[proposerPubkey]
}

func (ds *MemoryDatastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.entries[entry.Message.Pubkey] = &entry
}

func (ds *MemoryDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, entry := range entries {
		ds.entries[entry.Message.Pubkey] = &entry
	}
}

func NewMemoryDatastore() Datastore {
	return &MemoryDatastore{
		entries: make(map[types.PublicKey]*types.SignedValidatorRegistration),
	}
}
