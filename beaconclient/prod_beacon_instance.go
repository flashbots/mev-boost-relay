package beaconclient

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/capella"
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

// PayloadAttributesEvent represents the data of a payload_attributes event
// {"version": "capella", "data": {"proposer_index": "123", "proposal_slot": "10", "parent_block_number": "9", "parent_block_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "parent_block_hash": "0x9a2fefd2fdb57f74993c7780ea5b9030d2897b615b89f808011ca5aebed54eaf", "payload_attributes": {"timestamp": "123456", "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2", "suggested_fee_recipient": "0x0000000000000000000000000000000000000000", "withdrawals": [{"index": "5", "validator_index": "10", "address": "0x0000000000000000000000000000000000000000", "amount": "15640"}]}}}
type PayloadAttributesEvent struct {
	Version string                     `json:"version"`
	Data    PayloadAttributesEventData `json:"data"`
}

type PayloadAttributesEventData struct {
	ProposerIndex     uint64            `json:"proposer_index,string"`
	ProposalSlot      uint64            `json:"proposal_slot,string"`
	ParentBlockNumber uint64            `json:"parent_block_number,string"`
	ParentBlockRoot   string            `json:"parent_block_root"`
	ParentBlockHash   string            `json:"parent_block_hash"`
	PayloadAttributes PayloadAttributes `json:"payload_attributes"`
}

type PayloadAttributes struct {
	Timestamp             uint64                `json:"timestamp,string"`
	PrevRandao            string                `json:"prev_randao"`
	SuggestedFeeRecipient string                `json:"suggested_fee_recipient"`
	Withdrawals           []*capella.Withdrawal `json:"withdrawals"`
}

func (c *ProdBeaconInstance) SubscribeToHeadEvents(slotC chan HeadEventData) {
	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=head", c.beaconURI)
	log := c.log.WithField("url", eventsURL)
	log.Info("subscribing to head events")

	client := sse.NewClient(eventsURL)

	for {
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
		c.log.Warn("beaconclient SubscribeRaw/SubscribeToHeadEvents ended, reconnecting")
		time.Sleep(500 * time.Millisecond)
	}
}

func (c *ProdBeaconInstance) SubscribeToPayloadAttributesEvents(payloadAttributesC chan PayloadAttributesEvent) {
	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=payload_attributes", c.beaconURI)
	log := c.log.WithField("url", eventsURL)
	log.Info("subscribing to payload_attributes events")

	client := sse.NewClient(eventsURL)

	for {
		err := client.SubscribeRaw(func(msg *sse.Event) {
			var data PayloadAttributesEvent
			err := json.Unmarshal(msg.Data, &data)
			if err != nil {
				log.WithError(err).Error("could not unmarshal payload_attributes event")
			} else {
				payloadAttributesC <- data
			}
		})
		if err != nil {
			log.WithError(err).Error("failed to subscribe to payload_attributes events")
			time.Sleep(1 * time.Second)
		}
		c.log.Warn("beaconclient SubscribeRaw/SubscribeToPayloadAttributesEvents ended, reconnecting")
		time.Sleep(500 * time.Millisecond)
	}
}

type GetStateValidatorsResponse struct {
	ExecutionOptimistic bool `json:"execution_optimistic"`
	Finalized           bool `json:"finalized"`
	Data                []ValidatorResponseEntry
}

type ValidatorResponseEntry struct {
	Index     uint64                         `json:"index,string"` // Index of validator in validator registry.
	Balance   string                         `json:"balance"`      // Current validator balance in gwei.
	Status    string                         `json:"status"`
	Validator ValidatorResponseValidatorData `json:"validator"`
}

type ValidatorResponseValidatorData struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	EffectiveBalance      string `json:"effective_balance"`
	Slashed               bool   `json:"slashed"`
	ActivationEligibility uint64 `json:"activation_eligibility_epoch,string"`
	ActivationEpoch       uint64 `json:"activation_epoch,string"`
	ExitEpoch             uint64 `json:"exit_epoch,string"`
	WithdrawableEpoch     uint64 `json:"withdrawable_epoch,string"`
}

// GetStateValidators loads all active and pending validators
// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
func (c *ProdBeaconInstance) GetStateValidators(stateID string) (*GetStateValidatorsResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/states/%s/validators?status=active,pending", c.beaconURI, stateID)
	vd := new(GetStateValidatorsResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, vd, nil)
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
	timeout := 5 * time.Second
	resp := new(SyncStatusPayload)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, &timeout)
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
	Slot           uint64 `json:"slot,string"`
	Pubkey         string `json:"pubkey"`
	ValidatorIndex uint64 `json:"validator_index,string"`
}

// GetProposerDuties returns proposer duties for every slot in this epoch
// https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties
func (c *ProdBeaconInstance) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", c.beaconURI, epoch)
	resp := new(ProposerDutiesResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, nil)
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
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

// GetHeaderForSlot returns the header for a given slot - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
func (c *ProdBeaconInstance) GetHeaderForSlot(slot uint64) (*GetHeaderResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/headers/%d", c.beaconURI, slot)
	resp := new(GetHeaderResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

type GetBlockResponse struct {
	Data struct {
		Message struct {
			Slot uint64 `json:"slot,string"`
			Body struct {
				ExecutionPayload capella.ExecutionPayload `json:"execution_payload"`
			}
		}
	}
}

// GetBlock returns a block - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
// blockID can be 'head' or slot number
func (c *ProdBeaconInstance) GetBlock(blockID string) (block *GetBlockResponse, err error) {
	uri := fmt.Sprintf("%s/eth/v2/beacon/blocks/%s", c.beaconURI, blockID)
	resp := new(GetBlockResponse)
	_, err = fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

// GetBlockForSlot returns the block for a given slot - https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2
func (c *ProdBeaconInstance) GetBlockForSlot(slot uint64) (*GetBlockResponse, error) {
	uri := fmt.Sprintf("%s/eth/v2/beacon/blocks/%d", c.beaconURI, slot)
	resp := new(GetBlockResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

func (c *ProdBeaconInstance) GetURI() string {
	return c.beaconURI
}

func (c *ProdBeaconInstance) PublishBlock(block *spec.VersionedSignedBeaconBlock) (code int, err error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/blocks", c.beaconURI)
	return fetchBeacon(http.MethodPost, uri, block, nil, nil)
}

type GetGenesisResponse struct {
	Data GetGenesisResponseData `json:"data"`
}

type GetGenesisResponseData struct {
	GenesisTime           uint64 `json:"genesis_time,string"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion    string `json:"genesis_fork_version"`
}

// GetGenesis returns the genesis info - https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis
func (c *ProdBeaconInstance) GetGenesis() (*GetGenesisResponse, error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/genesis", c.beaconURI)
	resp := new(GetGenesisResponse)
	_, err := fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

type GetSpecResponse struct {
	SecondsPerSlot                  uint64 `json:"SECONDS_PER_SLOT,string"`            //nolint:tagliatelle
	DepositContractAddress          string `json:"DEPOSIT_CONTRACT_ADDRESS"`           //nolint:tagliatelle
	DepositNetworkID                string `json:"DEPOSIT_NETWORK_ID"`                 //nolint:tagliatelle
	DomainAggregateAndProof         string `json:"DOMAIN_AGGREGATE_AND_PROOF"`         //nolint:tagliatelle
	InactivityPenaltyQuotient       string `json:"INACTIVITY_PENALTY_QUOTIENT"`        //nolint:tagliatelle
	InactivityPenaltyQuotientAltair string `json:"INACTIVITY_PENALTY_QUOTIENT_ALTAIR"` //nolint:tagliatelle
}

// GetSpec - https://ethereum.github.io/beacon-APIs/#/Config/getSpec
func (c *ProdBeaconInstance) GetSpec() (spec *GetSpecResponse, err error) {
	uri := fmt.Sprintf("%s/eth/v1/config/spec", c.beaconURI)
	resp := new(GetSpecResponse)
	_, err = fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

type GetForkScheduleResponse struct {
	Data []struct {
		PreviousVersion string `json:"previous_version"`
		CurrentVersion  string `json:"current_version"`
		Epoch           uint64 `json:"epoch,string"`
	}
}

// GetForkSchedule - https://ethereum.github.io/beacon-APIs/#/Config/getForkSchedule
func (c *ProdBeaconInstance) GetForkSchedule() (spec *GetForkScheduleResponse, err error) {
	uri := fmt.Sprintf("%s/eth/v1/config/fork_schedule", c.beaconURI)
	resp := new(GetForkScheduleResponse)
	_, err = fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

type GetRandaoResponse struct {
	Data struct {
		Randao string `json:"randao"`
	}
}

// GetRandao - /eth/v1/beacon/states/<slot>/randao
func (c *ProdBeaconInstance) GetRandao(slot uint64) (randaoResp *GetRandaoResponse, err error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/states/%d/randao", c.beaconURI, slot)
	resp := new(GetRandaoResponse)
	_, err = fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}

type GetWithdrawalsResponse struct {
	Data struct {
		Withdrawals []*capella.Withdrawal `json:"withdrawals"`
	}
}

// GetWithdrawals - /eth/v1/beacon/states/<slot>/withdrawals
func (c *ProdBeaconInstance) GetWithdrawals(slot uint64) (withdrawalsResp *GetWithdrawalsResponse, err error) {
	uri := fmt.Sprintf("%s/eth/v1/beacon/states/%d/withdrawals", c.beaconURI, slot)
	resp := new(GetWithdrawalsResponse)
	_, err = fetchBeacon(http.MethodGet, uri, nil, resp, nil)
	return resp, err
}
