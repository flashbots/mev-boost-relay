package beaconclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/r3labs/sse/v2"
	"github.com/sirupsen/logrus"
)

type ProdBeaconInstance struct {
	log       *logrus.Entry
	beaconURI string
}

func NewProdBeaconInstance(log *logrus.Entry, beaconURI string) *ProdBeaconInstance {
	_log := log.WithFields(logrus.Fields{
		"component": "beaconInstance",
		"beaconURI": beaconURI,
	})
	return &ProdBeaconInstance{_log, beaconURI}
}

// HeadEventData represents the data of a head event
// {"slot":"827256","block":"0x56b683afa68170c775f3c9debc18a6a72caea9055584d037333a6fe43c8ceb83","state":"0x419e2965320d69c4213782dae73941de802a4f436408fddd6f68b671b3ff4e55","epoch_transition":false,"execution_optimistic":false,"previous_duty_dependent_root":"0x5b81a526839b7fb67c3896f1125451755088fb578ad27c2690b3209f3d7c6b54","current_duty_dependent_root":"0x5f3232c0d5741e27e13754e1d88285c603b07dd6164b35ca57e94344a9e42942"}
type HeadEventData struct {
	Slot  uint64 `json:"slot,string"`
	Block string `json:"block"`
	State string `json:"state"`
}

func (c *ProdBeaconInstance) SubscribeToHeadEvents(slotC chan HeadEventData) {
	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=head", c.beaconURI)
	log := c.log.WithField("url", eventsURL)
	log.Info("subscribing to head events")

	for {
		client := sse.NewClient(eventsURL)
		err := client.SubscribeRaw(func(msg *sse.Event) {
			var data HeadEventData
			err := json.Unmarshal(msg.Data, &data)
			if err != nil {
				log.WithError(err).Error("could not unmarshal head event")
			} else {
				slotC <- data
			}
		})
		if err != nil {
			log.WithError(err).Error("failed to subscribe to head events")
			time.Sleep(1 * time.Second)
		}
		c.log.Warn("beaconclient SubscribeRaw ended, reconnecting")
	}
}

func (c *ProdBeaconInstance) FetchValidators(headSlot uint64) (map[types.PubkeyHex]ValidatorResponseEntry, error) {
	vd, err := fetchAllValidators(c.beaconURI, headSlot)
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

func fetchAllValidators(endpoint string, headSlot uint64) (*AllValidatorsResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/states/%d/validators?status=active,pending", endpoint, headSlot)
	// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
	vd := new(AllValidatorsResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, vd)
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
func (c *ProdBeaconInstance) SyncStatus() (*SyncStatusPayloadData, error) {
	uri := c.beaconURI + "/eth/v1/node/syncing"
	resp := new(SyncStatusPayload)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (c *ProdBeaconInstance) CurrentSlot() (uint64, error) {
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
func (c *ProdBeaconInstance) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", c.beaconURI, epoch)
	resp := new(ProposerDutiesResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}

type GetHeaderResponse struct {
	Data struct {
		Root   string `json:"root"`
		Header struct {
			Message *GetHeaderResponseMessage
		}
	}
}

type GetHeaderResponseMessage struct {
	Slot          uint64 `json:"slot,string"`
	ProposerIndex uint64 `json:"proposer_index,string"`
	ParentRoot    string `json:"parent_root"`
}

// GetHeader returns the latest header - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
func (c *ProdBeaconInstance) GetHeader() (*GetHeaderResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/headers/head", c.beaconURI)
	resp := new(GetHeaderResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}

// GetHeaderForSlot returns the header for a given slot - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
func (c *ProdBeaconInstance) GetHeaderForSlot(slot uint64) (*GetHeaderResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/headers/%d", c.beaconURI, slot)
	resp := new(GetHeaderResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}

type GetBlockResponse struct {
	Data struct {
		Message struct {
			Slot uint64 `json:"slot,string"`
			Body struct {
				ExecutionPayload types.ExecutionPayload `json:"execution_payload"`
			}
		}
	}
}

// GetBlock returns the latest block - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
func (c *ProdBeaconInstance) GetBlock() (*GetBlockResponse, error) {
	uri := fmt.Sprintf("%s/eth/v2/beacon/blocks/head", c.beaconURI)
	resp := new(GetBlockResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}

// GetBlockForSlot returns the block for a given slot - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
func (c *ProdBeaconInstance) GetBlockForSlot(slot uint64) (*GetBlockResponse, error) {
	uri := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", c.beaconURI, slot)
	resp := new(GetBlockResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}

func (c *ProdBeaconInstance) GetURI() string {
	return c.beaconURI
}

func (c *ProdBeaconInstance) PublishBlock(block *types.SignedBeaconBlock) (code int, err error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/blocks", c.beaconURI)
	return fetchBeacon(http.MethodPost, uri, block, nil)
}

type GetGenesisResponse struct {
	Data struct {
		GenesisTime           uint64 `json:"genesis_time,string"`
		GenesisValidatorsRoot string `json:"genesis_validators_root"`
		GenesisForkVersion    string `json:"genesis_fork_version"`
	}
}

// GetGenesis returns the genesis info - https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis
func (c *ProdBeaconInstance) GetGenesis() (*GetGenesisResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/genesis", c.beaconURI)
	resp := new(GetGenesisResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp)
	return resp, err
}
