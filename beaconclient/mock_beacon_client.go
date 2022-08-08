package beaconclient

import (
	"context"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
)

type MockBeaconClient struct {
	mu           sync.RWMutex
	validatorSet map[types.PubkeyHex]ValidatorResponseEntry
}

func NewMockBeaconClient() *MockBeaconClient {
	return &MockBeaconClient{
		validatorSet: make(map[types.PubkeyHex]ValidatorResponseEntry),
	}
}

func (c *MockBeaconClient) AddValidator(entry ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet[types.NewPubkeyHex(entry.Validator.Pubkey)] = entry
	c.mu.Unlock()
}

func (c *MockBeaconClient) SetValidators(validatorSet map[types.PubkeyHex]ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet = validatorSet
	c.mu.Unlock()
}

func (c *MockBeaconClient) IsValidator(pubkey types.PubkeyHex) bool {
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

func (c *MockBeaconClient) FetchValidators(context.Context) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	return c.validatorSet, nil
}

func (c *MockBeaconClient) SyncStatus(context.Context) (*SyncStatusPayloadData, error) {
	return &SyncStatusPayloadData{
		HeadSlot:  1,
		IsSyncing: false,
	}, nil
}

func (c *MockBeaconClient) CurrentSlot(context.Context) (uint64, error) {
	return 1, nil
}

func (c *MockBeaconClient) SubscribeToHeadEvents(ctx context.Context, slotC chan uint64) {}

func (c *MockBeaconClient) GetProposerDuties(ctx context.Context, epoch uint64) (*ProposerDutiesResponse, error) {
	return &ProposerDutiesResponse{}, nil
}
