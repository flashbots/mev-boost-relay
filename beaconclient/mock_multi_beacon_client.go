package beaconclient

import (
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
)

type MockMultiBeaconClient struct{}

func NewMockMultiBeaconClient() *MockMultiBeaconClient {
	return &MockMultiBeaconClient{}
}

func (*MockMultiBeaconClient) BestSyncStatus() (*SyncStatusPayloadData, error) {
	return &SyncStatusPayloadData{HeadSlot: 1}, nil //nolint:exhaustruct
}

func (*MockMultiBeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {}

func (*MockMultiBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan PayloadAttributesEvent) {
}

func (*MockMultiBeaconClient) GetStateValidators(stateID string) (*GetStateValidatorsResponse, error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	return nil, nil
}

func (*MockMultiBeaconClient) PublishBlock(block *common.VersionedSignedProposal) (code int, err error) {
	return 0, nil
}

func (*MockMultiBeaconClient) GetGenesis() (*GetGenesisResponse, error) {
	resp := &GetGenesisResponse{} //nolint:exhaustruct
	resp.Data.GenesisTime = 0
	return resp, nil
}

func (*MockMultiBeaconClient) GetSpec() (spec *GetSpecResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetForkSchedule() (spec *GetForkScheduleResponse, err error) {
	resp := &GetForkScheduleResponse{
		Data: []struct {
			PreviousVersion string `json:"previous_version"`
			CurrentVersion  string `json:"current_version"`
			Epoch           uint64 `json:"epoch,string"`
		}{
			{
				CurrentVersion: "",
				Epoch:          1,
			},
		},
	}
	return resp, nil
}

func (*MockMultiBeaconClient) GetRandao(slot uint64) (spec *GetRandaoResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetWithdrawals(slot uint64) (spec *GetWithdrawalsResponse, err error) {
	resp := &GetWithdrawalsResponse{}                                            //nolint:exhaustruct
	resp.Data.Withdrawals = append(resp.Data.Withdrawals, &capella.Withdrawal{}) //nolint:exhaustruct
	return resp, nil
}
