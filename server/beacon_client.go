package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

type PubkeyHex string

type ValidatorService interface {
	IsValidator(PubkeyHex) bool
}

type BeaconClientValidatorService struct {
	beaconEndpoint string
	mu             sync.RWMutex
	validatorSet   map[PubkeyHex]struct{}
}

func NewBeaconClientValidatorService(beaconEndpoint string) *BeaconClientValidatorService {
	return &BeaconClientValidatorService{
		beaconEndpoint: beaconEndpoint,
		validatorSet:   make(map[PubkeyHex]struct{}),
	}
}

func (b *BeaconClientValidatorService) IsValidator(pubkey PubkeyHex) bool {
	b.mu.RLock()
	_, found := b.validatorSet[pubkey]
	b.mu.RUnlock()
	return found
}

func (b *BeaconClientValidatorService) FetchValidators() error {
	vd, err := fetchAllValidators(b.beaconEndpoint)
	if err != nil {
		return err
	}

	newValidatorSet := make(map[PubkeyHex]struct{})
	for _, vs := range vd.Data {
		newValidatorSet[PubkeyHex(vs.Validator.Pubkey)] = struct{}{}
	}

	b.mu.Lock()
	b.validatorSet = newValidatorSet
	b.mu.Unlock()
	return nil
}

type validatorData struct {
	Data []struct {
		Validator struct {
			Pubkey string `json:"pubkey"`
		} `json:"validator"`
	}
}

func fetchAllValidators(endpoint string) (*validatorData, error) {
	uri := endpoint + "/eth/v1/beacon/states/head/validators?status=active,pending"

	// https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators
	vd := new(validatorData)
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
