package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/r3labs/sse"
)

type PubkeyHex string

func NewPubkeyHex(pk string) PubkeyHex {
	return PubkeyHex(strings.ToLower(pk))
}

func (pk PubkeyHex) ToLower() PubkeyHex {
	return PubkeyHex(strings.ToLower(string(pk)))
}

type BeaconNodeService interface {
	SyncStatus() (*SyncStatusPayloadData, error)
	CurrentSlot() (uint64, error)
	SubscribeToHeadEvents(slotC chan uint64)
	IsValidator(PubkeyHex) bool
	NumValidators() uint64
	FetchValidators() error
}

type MockValidatorService struct {
	mu           sync.RWMutex
	validatorSet map[PubkeyHex]validatorResponseEntry
}

func (d *MockValidatorService) IsValidator(pubkey PubkeyHex) bool {
	d.mu.RLock()
	_, found := d.validatorSet[pubkey]
	d.mu.RUnlock()
	return found
}

func (d *MockValidatorService) NumValidators() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return uint64(len(d.validatorSet))
}

func (d *MockValidatorService) FetchValidators() error {
	return nil
}

func NewMockValidatorService(validatorSet map[PubkeyHex]validatorResponseEntry) *MockValidatorService {
	return &MockValidatorService{
		validatorSet: validatorSet,
	}
}

type ProdBeaconNodeService struct {
	beaconEndpoint string
	mu             sync.RWMutex
	validatorSet   map[PubkeyHex]validatorResponseEntry
}

func NewBeaconClientService(beaconEndpoint string) *ProdBeaconNodeService {
	return &ProdBeaconNodeService{
		beaconEndpoint: beaconEndpoint,
		validatorSet:   make(map[PubkeyHex]validatorResponseEntry),
	}
}

// HeadEventData represents the data of a head event
// {"slot":"827256","block":"0x56b683afa68170c775f3c9debc18a6a72caea9055584d037333a6fe43c8ceb83","state":"0x419e2965320d69c4213782dae73941de802a4f436408fddd6f68b671b3ff4e55","epoch_transition":false,"execution_optimistic":false,"previous_duty_dependent_root":"0x5b81a526839b7fb67c3896f1125451755088fb578ad27c2690b3209f3d7c6b54","current_duty_dependent_root":"0x5f3232c0d5741e27e13754e1d88285c603b07dd6164b35ca57e94344a9e42942"}
type HeadEventData struct {
	Slot uint64 `json:",string"`
}

func (b *ProdBeaconNodeService) SubscribeToHeadEvents(slotC chan uint64) {
	eventsURL := fmt.Sprintf("%s/eth/v1/events?topics=head", b.beaconEndpoint)
	client := sse.NewClient(eventsURL)
	client.SubscribeRaw(func(msg *sse.Event) {
		var data HeadEventData
		err := json.Unmarshal(msg.Data, &data)
		if err != nil {
			fmt.Println(err)
		} else {
			slotC <- data.Slot
		}
	})

}

func (b *ProdBeaconNodeService) IsValidator(pubkey PubkeyHex) bool {
	b.mu.RLock()
	_, found := b.validatorSet[pubkey.ToLower()]
	b.mu.RUnlock()
	return found
}

func (b *ProdBeaconNodeService) NumValidators() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return uint64(len(b.validatorSet))
}

func (b *ProdBeaconNodeService) FetchValidators() error {
	vd, err := fetchAllValidators(b.beaconEndpoint)
	if err != nil {
		return err
	}

	newValidatorSet := make(map[PubkeyHex]validatorResponseEntry)
	for _, vs := range vd.Data {
		newValidatorSet[NewPubkeyHex(vs.Validator.Pubkey)] = vs
	}

	b.mu.Lock()
	b.validatorSet = newValidatorSet
	b.mu.Unlock()
	return nil
}

type validatorResponseEntry struct {
	Validator validatorPubKeyEntry `json:"validator"`
}

type validatorPubKeyEntry struct {
	Pubkey string `json:"pubkey"`
}

type allValidatorsResponse struct {
	Data []validatorResponseEntry
}

func fetchAllValidators(endpoint string) (*allValidatorsResponse, error) {
	uri := endpoint + "/eth/v1/beacon/states/head/validators?status=active,pending"

	// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
	vd := new(allValidatorsResponse)
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
func (b *ProdBeaconNodeService) SyncStatus() (*SyncStatusPayloadData, error) {
	uri := b.beaconEndpoint + "/eth/v1/node/syncing"
	resp := new(SyncStatusPayload)
	err := fetchBeacon(uri, "GET", resp)
	if err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

func (b *ProdBeaconNodeService) CurrentSlot() (uint64, error) {
	syncStatus, err := b.SyncStatus()
	if err != nil {
		return 0, err
	}
	return syncStatus.HeadSlot, nil
}

// CurrentSlot() uint64

func fetchBeacon(url string, method string, dst any) error {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return fmt.Errorf("invalid reqest for %s: %w", url, err)
	}
	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("client refused for %s: %w", url, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("could not read response body for %s: %w", url, err)
	}

	if resp.StatusCode >= 300 {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			return fmt.Errorf("could not unmarshal error response from beacon node for %s from %s: %w", url, string(bodyBytes), err)
		}
		return errors.New(ec.Message)
	}

	err = json.Unmarshal(bodyBytes, dst)
	if err != nil {
		return fmt.Errorf("could not unmarshal response for %s from %s: %w", url, string(bodyBytes), err)
	}

	return nil
}
