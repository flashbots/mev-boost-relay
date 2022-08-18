package beaconclient

import (
	"sync"
	"time"

	"github.com/flashbots/go-boost-utils/types"
)

type MockBeaconClient struct {
	mu           sync.RWMutex
	validatorSet map[types.PubkeyHex]ValidatorResponseEntry

	MockSyncStatus         *SyncStatusPayloadData
	MockSyncStatusErr      error
	MockProposerDuties     *ProposerDutiesResponse
	MockProposerDutiesErr  error
	MockFetchValidatorsErr error

	ResponseDelay time.Duration
}

func NewMockBeaconClient() *MockBeaconClient {
	return &MockBeaconClient{
		validatorSet: make(map[types.PubkeyHex]ValidatorResponseEntry),
		MockSyncStatus: &SyncStatusPayloadData{
			HeadSlot:  1,
			IsSyncing: false,
		},
		MockProposerDuties: &ProposerDutiesResponse{
			Data: []ProposerDutiesResponseData{},
		},
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

func (c *MockBeaconClient) FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	c.addDelay()
	return c.validatorSet, c.MockFetchValidatorsErr
}

func (c *MockBeaconClient) SyncStatus() (*SyncStatusPayloadData, error) {
	c.addDelay()
	return c.MockSyncStatus, c.MockSyncStatusErr
}

func (c *MockBeaconClient) CurrentSlot() (uint64, error) {
	c.addDelay()
	return c.MockSyncStatus.HeadSlot, nil
}

func (c *MockBeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {}

func (c *MockBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	c.addDelay()
	return c.MockProposerDuties, c.MockProposerDutiesErr
}

func (c *MockBeaconClient) GetURI() string { return "" }

func (c *MockBeaconClient) addDelay() {
	if c.ResponseDelay > 0 {
		time.Sleep(c.ResponseDelay)
	}
}
