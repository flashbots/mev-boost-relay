package common

import (
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type Datastore interface {
	GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error)
	SaveValidatorRegistration(entry types.SignedValidatorRegistration) error
	SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error

	SetKnownValidator(pubkeyHex string) error
	IsKnwonValidator(pubkeyHex string) (bool, error)
}

type MemoryDatastore struct {
	registrations   map[types.PublicKey]*types.SignedValidatorRegistration
	knownValidators map[string]bool
	mu              sync.RWMutex

	// Used to count each request made to the datastore for each method
	requestCount map[string]int
}

func NewMemoryDatastore() Datastore {
	return &MemoryDatastore{
		registrations:   make(map[types.PublicKey]*types.SignedValidatorRegistration),
		knownValidators: make(map[string]bool),
	}
}

// GetValidatorRegistration returns the validator registration for the given proposerPubkey. If not found then it returns (nil, nil). If
// there's a datastore error, then an error will be returned.
func (ds *MemoryDatastore) GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	ds.requestCount["GetValidatorRegistration"]++
	return ds.registrations[proposerPubkey], nil
}

func (ds *MemoryDatastore) SaveValidatorRegistration(entry types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.requestCount["SaveValidatorRegistration"]++
	ds.registrations[entry.Message.Pubkey] = &entry
	return nil
}

func (ds *MemoryDatastore) SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.requestCount["SaveValidatorRegistrations"]++
	for _, entry := range entries {
		ds.registrations[entry.Message.Pubkey] = &entry
	}
	return nil
}

// GetRequestCount returns the number of Request made to a method
func (ds *MemoryDatastore) GetRequestCount(method string) int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.requestCount[method]
}

func (ds *MemoryDatastore) IsKnwonValidator(pubkeyHex string) (bool, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	_, ok := ds.knownValidators[pubkeyHex]
	return ok, nil
}

func (ds *MemoryDatastore) SetKnownValidator(pubkeyHex string) error {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.knownValidators[pubkeyHex] = true
	return nil
}
