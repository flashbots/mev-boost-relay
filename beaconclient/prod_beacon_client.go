package beaconclient

import (
	"encoding/json"
	"fmt"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/r3labs/sse/v2"
	"github.com/sirupsen/logrus"
)

type ProdBeaconClient struct {
	log       *logrus.Entry
	beaconURI string
}

func NewProdBeaconClient(log *logrus.Entry, beaconURI string) *ProdBeaconClient {
	_log := log.WithFields(logrus.Fields{
		"module":    "beaconClient",
		"beaconURI": beaconURI,
	})
	return &ProdBeaconClient{_log, beaconURI}
}

// HeadEventData represents the data of a head event
// {"slot":"827256","block":"0x56b683afa68170c775f3c9debc18a6a72caea9055584d037333a6fe43c8ceb83","state":"0x419e2965320d69c4213782dae73941de802a4f436408fddd6f68b671b3ff4e55","epoch_transition":false,"execution_optimistic":false,"previous_duty_dependent_root":"0x5b81a526839b7fb67c3896f1125451755088fb578ad27c2690b3209f3d7c6b54","current_duty_dependent_root":"0x5f3232c0d5741e27e13754e1d88285c603b07dd6164b35ca57e94344a9e42942"}
type HeadEventData struct {
	Slot uint64 `json:",string"`
}

func (c *ProdBeaconClient) SubscribeToHeadEvents(slotC chan uint64) {
	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=head", c.beaconURI)
	for {
		client := sse.NewClient(eventsURL)
		client.SubscribeRaw(func(msg *sse.Event) {
			var data HeadEventData
			err := json.Unmarshal(msg.Data, &data)
			if err != nil {
				c.log.WithError(err).Error("could not unmarshal head event")
			} else {
				slotC <- data.Slot
			}
		})
		c.log.Warn("beaconclient SubscribeRaw ended, reconnecting")
	}
}

func (c *ProdBeaconClient) FetchValidators() (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	vd, err := fetchAllValidators(c.beaconURI)
	if err != nil {
		return nil, err
	}

	newValidatorSet := make(map[types.PubkeyHex]ValidatorResponseEntry)
	for _, vs := range vd.Data {
		newValidatorSet[types.NewPubkeyHex(vs.Validator.Pubkey)] = vs
	}

	return newValidatorSet, nil
}

type ValidatorResponseEntry struct {
	Index     uint64                         `json:"index,string"` // Index of validator in validator registry.
	Balance   string                         `json:"balance"`      // Current validator balance in gwei.
	Status    string                         `json:"status"`
	Validator ValidatorResponseValidatorData `json:"validator"`
}

type ValidatorResponseValidatorData struct {
	Pubkey string `json:"pubkey"`
}

type AllValidatorsResponse struct {
	Data []ValidatorResponseEntry
}

func fetchAllValidators(endpoint string) (*AllValidatorsResponse, error) {
	uri := endpoint + "/eth/v1/beacon/states/head/validators?status=active,pending"

	// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
	vd := new(AllValidatorsResponse)
	err := fetchBeacon(uri, "GET", vd)
	return vd, err
}

// SyncStatusPayload is the response payload for /eth/v1/node/syncing
// {"data":{"head_slot":"251114","sync_distance":"0","is_syncing":false,"is_optimistic":false}}
type SyncStatusPayload struct {
	Data SyncStatusPayloadData
}

type SyncStatusPayloadData struct {
	HeadSlot  uint64 `json:"head_slot,string"`
	IsSyncing bool   `json:"is_syncing"`
}

// SyncStatus returns the current node sync-status
// https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/getSyncingStatus
func (c *ProdBeaconClient) SyncStatus() (*SyncStatusPayloadData, error) {
	uri := c.beaconURI + "/eth/v1/node/syncing"
	resp := new(SyncStatusPayload)
	err := fetchBeacon(uri, "GET", resp)
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProdBeaconClient) CurrentSlot() (uint64, error) {
	syncStatus, err := c.SyncStatus()
	if err != nil {
		return 0, err
	}
	return syncStatus.HeadSlot, nil
}

type ProposerDutiesResponse struct {
	Data []ProposerDutiesResponseData
}

type ProposerDutiesResponseData struct {
	Pubkey string `json:"pubkey"`
	Slot   uint64 `json:"slot,string"`
}

// GetProposerDuties returns proposer duties for every slot in this epoch
// https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties
func (c *ProdBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", c.beaconURI, epoch)
	resp := new(ProposerDutiesResponse)
	err := fetchBeacon(uri, "GET", resp)
	return resp, err
}
