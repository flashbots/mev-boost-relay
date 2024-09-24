package mevcommitclientz

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	validatoroptinrouter "github.com/primev/mev-commit/contracts-abi/clients/ValidatorOptInRouter"
)

type IMevCommitClient interface {
	// Need to provide some SLA's around response times here. Should be down to milliseconds with memcache.
	GetOptInStatusForValidators(pubkeys [][]byte) (map[string]bool, error)
	IsBuilderRegistered(pubkey string) (bool, error)
	GetRegisteredValidators() ([]string, error)
}

type MevCommitClient struct {
	L1Address                  string // 0x5d4fC7B5Aeea4CF4F0Ca6Be09A2F5AaDAd2F2803 created at 1731009 block
	MevCommitAddress           string
	validatorOptInRouterCaller *validatoroptinrouter.ValidatoroptinrouterCaller
}

func NewMevCommitClient(apiUrl string, contractAddress string, client *ethclient.Client) (IMevCommitClient, error) {

	validatorOptInRouter, err := validatoroptinrouter.NewValidatoroptinrouterCaller(common.HexToAddress(contractAddress), client)
	if err != nil {
		return nil, err
	}

	return &MevCommitClient{
		validatorOptInRouterCaller: validatorOptInRouter,
	}, nil
}

func (m *MevCommitClient) GetOptInStatusForValidators(pubkeys [][]byte) (map[string]bool, error) {
	optedIn, err := m.validatorOptInRouterCaller.AreValidatorsOptedIn(nil, pubkeys)
	if err != nil {
		return nil, err
	}

	pubkeyMap := make(map[string]bool)
	for i, pubkey := range pubkeys {
		pubkeyMap[string(pubkey)] = optedIn[i]
	}
	return pubkeyMap, nil
}

func (m *MevCommitClient) IsBuilderRegistered(pubkey string) (bool, error) {
	return false, nil
}

func (m *MevCommitClient) GetRegisteredValidators() ([]string, error) {
	return nil, nil
}
