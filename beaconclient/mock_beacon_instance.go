package beaconclient

import (
	"sync"
	"time"

	"github.com/flashbots/mev-boost-relay/common"
)

type MockBeaconInstance struct {
	mu           sync.RWMutex
	validatorSet map[common.PubkeyHex]ValidatorResponseEntry

	MockSyncStatus         *SyncStatusPayloadData
	MockSyncStatusErr      error
	MockProposerDuties     *ProposerDutiesResponse
	MockProposerDutiesErr  error
	MockFetchValidatorsErr error

	ResponseDelay time.Duration
}

func NewMockBeaconInstance() *MockBeaconInstance {
	return &MockBeaconInstance{
		validatorSet: make(map[common.PubkeyHex]ValidatorResponseEntry),

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
	c.validatorSet[common.NewPubkeyHex(entry.Validator.Pubkey)] = entry
	c.mu.Unlock()
}

func (c *MockBeaconInstance) SetValidators(validatorSet map[common.PubkeyHex]ValidatorResponseEntry) {
	c.mu.Lock()
	c.validatorSet = validatorSet
	c.mu.Unlock()
}

func (c *MockBeaconInstance) IsValidator(pubkey common.PubkeyHex) bool {
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

func (c *MockBeaconInstance) GetStateValidators(stateID string) (*GetStateValidatorsResponse, error) {
	c.addDelay()
	validatorResp := &GetStateValidatorsResponse{ //nolint:exhaustruct
		Data: make([]ValidatorResponseEntry, 0),
	}
	for _, entry := range c.validatorSet {
		validatorResp.Data = append(validatorResp.Data, entry)
	}
	return validatorResp, c.MockFetchValidatorsErr
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

func (c *MockBeaconInstance) SubscribeToPayloadAttributesEvents(slotC chan PayloadAttributesEvent) {}

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

func (c *MockBeaconInstance) PublishBlock(block *common.VersionedSignedProposal, broadcaseMode BroadcastMode) (code int, err error) {
	return 0, nil
}

func (c *MockBeaconInstance) GetGenesis() (*GetGenesisResponse, error) {
	return nil, nil
}

func (c *MockBeaconInstance) GetSpec() (spec *GetSpecResponse, err error) {
	return nil, nil
}

func (c *MockBeaconInstance) GetForkSchedule() (spec *GetForkScheduleResponse, err error) {
	return nil, nil
}

func (c *MockBeaconInstance) GetRandao(slot uint64) (spec *GetRandaoResponse, err error) {
	return nil, nil
}

func (c *MockBeaconInstance) GetWithdrawals(slot uint64) (spec *GetWithdrawalsResponse, err error) {
	return nil, nil
}
