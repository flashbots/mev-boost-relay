package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

type PubkeyHex string

func NewPubkeyHex(pk string) PubkeyHex {
	return PubkeyHex(strings.ToLower(pk))
}

func (pk PubkeyHex) ToLower() PubkeyHex {
	return PubkeyHex(strings.ToLower(string(pk)))
}

type ValidatorService interface {
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

type BeaconClientValidatorService struct {
	beaconEndpoint string
	mu             sync.RWMutex
	validatorSet   map[PubkeyHex]validatorResponseEntry
}

func NewBeaconClientValidatorService(beaconEndpoint string) *BeaconClientValidatorService {
	return &BeaconClientValidatorService{
		beaconEndpoint: beaconEndpoint,
		validatorSet:   make(map[PubkeyHex]validatorResponseEntry),
	}
}

func (b *BeaconClientValidatorService) IsValidator(pubkey PubkeyHex) bool {
	b.mu.RLock()
	_, found := b.validatorSet[pubkey.ToLower()]
	b.mu.RUnlock()
	return found
}

func (b *BeaconClientValidatorService) NumValidators() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return uint64(len(b.validatorSet))
}

func (b *BeaconClientValidatorService) FetchValidators() error {
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
