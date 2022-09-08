package beaconclient

import (
	"sync"
	"time"

	"github.com/flashbots/go-boost-utils/types"
)

type MockBeaconInstance struct {
	mu           sync.RWMutex
	validatorSet map[types.PubkeyHex]ValidatorResponseEntry

	MockSyncStatus         *SyncStatusPayloadData
	MockSyncStatusErr      error
	MockProposerDuties     *ProposerDutiesResponse
	MockProposerDutiesErr  error
	MockFetchValidatorsErr error

	ResponseDelay time.Duration
}

func NewMockBeaconInstance() *MockBeaconInstance {
	return &MockBeaconInstance{
		validatorSet: make(map[types.PubkeyHex]ValidatorResponseEntry),

		MockSyncStatus: &SyncStatusPayloadData{
			HeadSlot:  1,
			IsSyncing: false,
		},
		MockProposerDuties: &ProposerDutiesResponse{
			Data: []ProposerDutiesResponseData{},
		},
		MockSyncStatusErr:      nil,
		MockProposerDutiesErr:  nil,
		MockFetchValidatorsErr: nil,

		ResponseDelay: 0,

		mu: sync.RWMutex{},
	}
}

func (c *MockBeaconInstance) AddValidator(entry ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet[types.NewPubkeyHex(entry.Validator.Pubkey)] = entry
	c.mu.Unlock()
}

func (c *MockBeaconInstance) SetValidators(validatorSet map[types.PubkeyHex]ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet = validatorSet
	c.mu.Unlock()
}

func (c *MockBeaconInstance) IsValidator(pubkey types.PubkeyHex) bool {
	c.mu.RLock()
	_, found := c.validatorSet[pubkey]
	c.mu.RUnlock()
	return found
}

func (c *MockBeaconInstance) NumValidators() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return uint64(len(c.validatorSet))
}

func (c *MockBeaconInstance) FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	c.addDelay()
	return c.validatorSet, c.MockFetchValidatorsErr
}

func (c *MockBeaconInstance) SyncStatus() (*SyncStatusPayloadData, error) {
	c.addDelay()
	return c.MockSyncStatus, c.MockSyncStatusErr
}

func (c *MockBeaconInstance) CurrentSlot() (uint64, error) {
	c.addDelay()
	return c.MockSyncStatus.HeadSlot, nil
}

func (c *MockBeaconInstance) SubscribeToHeadEvents(slotC chan HeadEventData) {}

func (c *MockBeaconInstance) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	c.addDelay()
	return c.MockProposerDuties, c.MockProposerDutiesErr
}

func (c *MockBeaconInstance) GetURI() string {
	return ""
}

func (c *MockBeaconInstance) addDelay() {
	if c.ResponseDelay > 0 {
		time.Sleep(c.ResponseDelay)
	}
}

func (c *MockBeaconInstance) PublishBlock(block *types.SignedBeaconBlock) (code int, err error) {
	return 0, nil
}
