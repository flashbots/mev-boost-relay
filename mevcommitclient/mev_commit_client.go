package mevcommitclient

import (
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	builderRegistry "github.com/primev/mev-commit/contracts-abi/clients/ProviderRegistry"
	validatoroptinrouter "github.com/primev/mev-commit/contracts-abi/clients/ValidatorOptInRouter"
)

type BuilderRegisteredEvent struct {
	Builder      common.Address
	Value        *big.Int
	BlsPublicKey []byte
	BlockNumber  uint64
	TxHash       common.Hash
	Timestamp    time.Time
	IsValid      bool
}

type IMevCommitClient interface {
	GetOptInStatusForValidators(pubkeys [][]byte) ([]bool, error)
	GetActiveBuilders() ([]common.Address, error)
}

type MevCommitClient struct {
	L1Address                  string
	MevCommitAddress           string
	ValidatorRouterAddress     common.Address
	BuilderRegistryAddress     common.Address
	validatorOptInRouterCaller *validatoroptinrouter.ValidatoroptinrouterCaller
	builderRegistryCaller      *builderRegistry.ProviderregistryCaller
	builderRegistryFilterer    *builderRegistry.ProviderregistryFilterer
	l1Client                   *ethclient.Client
	mevCommitClient            *ethclient.Client
	contractAbi                abi.ABI
}

const (
	abiJSON = `[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"builder","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"blsPublicKey","type":"bytes"}],"name":"BuilderRegistered","type":"event"},{"inputs":[{"internalType":"address","name":"builder","type":"address"}],"name":"isBuilderValid","outputs":[],"stateMutability":"view","type":"function"}]`
)

func NewMevCommitClient(l1MainnetUrl, mevCommitUrl string, validatorRouterAddress, builderRegistryAddress common.Address) (IMevCommitClient, error) {
	l1Client, err := ethclient.Dial(l1MainnetUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to L1 Mainnet: %w", err)
	}

	mevCommitClient, err := ethclient.Dial(mevCommitUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MEV-Commit EVM: %w", err)
	}

	validatorOptInRouter, err := validatoroptinrouter.NewValidatoroptinrouterCaller(validatorRouterAddress, l1Client)
	if err != nil {
		return nil, fmt.Errorf("failed to create ValidatorOptInRouter caller: %w", err)
	}

	builderRegistryCaller, err := builderRegistry.NewProviderregistryCaller(builderRegistryAddress, mevCommitClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create BuilderRegistry caller: %w", err)
	}

	builderRegistryFilterer, err := builderRegistry.NewProviderregistryFilterer(builderRegistryAddress, mevCommitClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create BuilderRegistry filterer: %w", err)
	}

	contractAbi, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to parse contract ABI: %w", err)
	}

	return &MevCommitClient{
		L1Address:                  l1MainnetUrl,
		MevCommitAddress:           mevCommitUrl,
		ValidatorRouterAddress:     validatorRouterAddress,
		BuilderRegistryAddress:     builderRegistryAddress,
		validatorOptInRouterCaller: validatorOptInRouter,
		builderRegistryCaller:      builderRegistryCaller,
		builderRegistryFilterer:    builderRegistryFilterer,
		l1Client:                   l1Client,
		mevCommitClient:            mevCommitClient,
		contractAbi:                contractAbi,
	}, nil
}

func (m *MevCommitClient) GetOptInStatusForValidators(pubkeys [][]byte) ([]bool, error) {
	return m.validatorOptInRouterCaller.AreValidatorsOptedIn(nil, pubkeys)
}

func (m *MevCommitClient) GetActiveBuilders() ([]common.Address, error) {
	opts := &bind.FilterOpts{
		Start: 0,
		End:   nil, // Latest block
	}

	iterator, err := m.builderRegistryFilterer.FilterProviderRegistered(opts, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to filter ProviderRegistered events: %w", err)
	}
	defer iterator.Close()

	activeBuilders := make([]common.Address, 0)
	for iterator.Next() {
		isValid, err := m.isBuilderValid(iterator.Event.Provider)
		if err != nil {
			return nil, fmt.Errorf("failed to check if builder is valid: %w", err)
		}
		if isValid {
			activeBuilders = append(activeBuilders, iterator.Event.Provider)
		}
	}

	if err := iterator.Error(); err != nil {
		return nil, fmt.Errorf("error iterating over ProviderRegistered events: %w", err)
	}

	return activeBuilders, nil
}

func (m *MevCommitClient) isBuilderValid(builderAddress common.Address) (bool, error) {
	err := m.builderRegistryCaller.IsProviderValid(nil, builderAddress)
	if err != nil {
		if err.Error() == "execution reverted" {
			return false, nil
		}
		return false, fmt.Errorf("error checking if builder is valid: %w", err)
	}
	return true, nil
}
