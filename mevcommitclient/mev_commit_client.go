package mevcommitclient

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	providerRegistry "github.com/primev/mev-commit/contracts-abi/clients/ProviderRegistry"
	validatoroptinrouter "github.com/primev/mev-commit/contracts-abi/clients/ValidatorOptInRouter"
)

type MevCommitProvider struct {
	Pubkey     []byte
	EOAAddress common.Address
}

type IMevCommitClient interface {
	GetOptInStatusForValidators(pubkeys [][]byte) ([]bool, error)
	ListenForBuildersEvents() (<-chan MevCommitProvider, <-chan common.Address, error)
	IsBuilderValid(builderAddress common.Address) (bool, error)
}

type MevCommitClient struct {
	L1Address                  string
	MevCommitAddress           string
	ValidatorRouterAddress     common.Address
	ProviderRegistryAddress    common.Address
	validatorOptInRouterCaller *validatoroptinrouter.ValidatoroptinrouterCaller
	builderRegistryCaller      *providerRegistry.ProviderregistryCaller
	builderRegistryFilterer    *providerRegistry.ProviderregistryFilterer
	l1Client                   *ethclient.Client
	mevCommitClient            *ethclient.Client
	contractAbi                abi.ABI
}

const (
	abiJSON = `[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"builder","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"blsPublicKey","type":"bytes"}],"name":"BuilderRegistered","type":"event"},{"inputs":[{"internalType":"address","name":"builder","type":"address"}],"name":"isBuilderValid","outputs":[],"stateMutability":"view","type":"function"}]`
)

func NewMevCommitClient(l1MainnetUrl, mevCommitUrl string, validatorRouterAddress, ProviderRegistryAddress common.Address) (IMevCommitClient, error) {
	l1Client, err := ethclient.Dial(l1MainnetUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to L1 Mainnet: %w", err)
	}

	mevCommitClient, err := ethclient.Dial(mevCommitUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to mev-commit EVM: %w", err)
	}

	validatorOptInRouter, err := validatoroptinrouter.NewValidatoroptinrouterCaller(validatorRouterAddress, l1Client)
	if err != nil {
		return nil, fmt.Errorf("failed to create ValidatorOptInRouter caller: %w", err)
	}

	builderRegistryCaller, err := providerRegistry.NewProviderregistryCaller(ProviderRegistryAddress, mevCommitClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create BuilderRegistry caller: %w", err)
	}

	builderRegistryFilterer, err := providerRegistry.NewProviderregistryFilterer(ProviderRegistryAddress, mevCommitClient)
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
		ProviderRegistryAddress:    ProviderRegistryAddress,
		validatorOptInRouterCaller: validatorOptInRouter,
		builderRegistryCaller:      builderRegistryCaller,
		builderRegistryFilterer:    builderRegistryFilterer,
		l1Client:                   l1Client,
		mevCommitClient:            mevCommitClient,
		contractAbi:                contractAbi,
	}, nil
}

func (m *MevCommitClient) GetOptInStatusForValidators(pubkeys [][]byte) ([]bool, error) {
	// Get the finalized block number
	var finalizedBlockNumber *big.Int
	err := m.l1Client.Client().Call(&finalizedBlockNumber, "eth_getBlockByNumber", "finalized", false)
	if err != nil {
		return nil, fmt.Errorf("failed to get finalized block: %w", err)
	}

	opts := &bind.CallOpts{
		BlockNumber: finalizedBlockNumber,
	}

	return m.validatorOptInRouterCaller.AreValidatorsOptedIn(opts, pubkeys)
}

func (m *MevCommitClient) ListenForBuildersEvents() (<-chan MevCommitProvider, <-chan common.Address, error) {
	opts := &bind.WatchOpts{
		Start:   nil, // Start from the latest block
		Context: context.Background(),
	}
	builderRegistryEventCh := make(chan MevCommitProvider)
	builderUnregisteredEventCh := make(chan common.Address)

	providerRegisteredEventCh := make(chan *providerRegistry.ProviderregistryProviderRegistered)
	providerSlashedEventCh := make(chan *providerRegistry.ProviderregistryFundsSlashed)

	providerRegisteredSub, err := m.builderRegistryFilterer.WatchProviderRegistered(opts, providerRegisteredEventCh, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to watch ProviderRegistered events: %w", err)
	}

	providerSlashedSub, err := m.builderRegistryFilterer.WatchFundsSlashed(opts, providerSlashedEventCh, nil)
	if err != nil {
		providerRegisteredSub.Unsubscribe()
		return nil, nil, fmt.Errorf("failed to watch ProviderSlashed events: %w", err)
	}

	go func() {
		defer providerRegisteredSub.Unsubscribe()
		for {
			select {
			case err := <-providerRegisteredSub.Err():
				fmt.Printf("error while watching ProviderRegistered events: %v\n", err)
				close(builderRegistryEventCh)
				return
			case event := <-providerRegisteredEventCh:
				isValid, err := m.IsBuilderValid(event.Provider)
				if err != nil {
					fmt.Printf("failed to check if builder is valid: %v\n", err)
					continue
				}
				if isValid {
					builderRegistryEventCh <- MevCommitProvider{
						Pubkey:     event.BlsPublicKey,
						EOAAddress: event.Provider,
					}
				}
			}
		}
	}()

	go func() {
		defer providerSlashedSub.Unsubscribe()
		for {
			select {
			case err := <-providerSlashedSub.Err():
				fmt.Printf("error while watching ProviderSlashed events: %v\n", err)
				close(builderUnregisteredEventCh)
				return
			case event := <-providerSlashedEventCh:
				isValid, err := m.IsBuilderValid(event.Provider)
				if err != nil {
					fmt.Printf("failed to check if builder is valid: %v\n", err)
					continue
				}
				if !isValid {
					builderUnregisteredEventCh <- event.Provider
				}
			}
		}
	}()

	return builderRegistryEventCh, builderUnregisteredEventCh, nil
}

func (m *MevCommitClient) IsBuilderValid(builderAddress common.Address) (bool, error) {
	err := m.builderRegistryCaller.IsProviderValid(nil, builderAddress)
	if err != nil {
		if err.Error() == "execution reverted" {
			return false, nil
		}
		return false, fmt.Errorf("error checking if builder is valid: %w", err)
	}
	return true, nil
}
