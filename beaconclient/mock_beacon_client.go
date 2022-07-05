package beaconclient

import (
	"sync"

	"github.com/flashbots/boost-relay/common"
)

type MockBeaconClient struct {
	mu           sync.RWMutex
	validatorSet map[common.PubkeyHex]ValidatorResponseEntry
}

func NewMockBeaconClient() *MockBeaconClient {
	return &MockBeaconClient{
		validatorSet: make(map[common.PubkeyHex]ValidatorResponseEntry),
	}
}

func (c *MockBeaconClient) AddValidator(entry ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet[common.NewPubkeyHex(entry.Validator.Pubkey)] = entry
	c.mu.Unlock()
}

func (c *MockBeaconClient) SetValidators(validatorSet map[common.PubkeyHex]ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet = validatorSet
	c.mu.Unlock()
}

func (c *MockBeaconClient) IsValidator(pubkey common.PubkeyHex) bool {
	c.mu.RLock()
	_, found := c.validatorSet[pubkey]
	c.mu.RUnlock()
	return found
}

func (c *MockBeaconClient) NumValidators() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(len(c.validatorSet))
}

func (c *MockBeaconClient) FetchValidators() (map[common.PubkeyHex]ValidatorResponseEntry, error) {
	return c.validatorSet, nil
}

func (c *MockBeaconClient) SyncStatus() (*SyncStatusPayloadData, error) {
	return &SyncStatusPayloadData{
		HeadSlot:  1,
		IsSyncing: false,
	}, nil
}

func (c *MockBeaconClient) CurrentSlot() (uint64, error) {
	return 1, nil
}

func (c *MockBeaconClient) SubscribeToHeadEvents(slotC chan uint64) {}
