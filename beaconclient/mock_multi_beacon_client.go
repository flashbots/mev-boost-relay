package beaconclient

import (
	"github.com/flashbots/go-boost-utils/types"
)

type MockMultiBeaconClient struct{}

func NewMockMultiBeaconClient() *MockMultiBeaconClient {
	return &MockMultiBeaconClient{}
}

func (*MockMultiBeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {}

func (*MockMultiBeaconClient) BestSyncStatus() (*SyncStatusPayloadData, error) {
	return &SyncStatusPayloadData{HeadSlot: 1}, nil
}

func (*MockMultiBeaconClient) FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	return nil, nil
}

func (*MockMultiBeaconClient) PublishBlock(block *types.SignedBeaconBlock) (code int, err error) {
	return 0, nil
}

func (*MockMultiBeaconClient) GetGenesis() (*GetGenesisResponse, error) {
	resp := &GetGenesisResponse{}
	resp.Data.GenesisTime = 0
	return resp, nil
}

func (*MockMultiBeaconClient) GetSpec() (spec *GetSpecResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetBlock(blockID string) (block *GetBlockResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetRandao(slot uint64) (spec *GetRandaoResponse, err error) {
	return nil, nil
}
