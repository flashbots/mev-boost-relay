// Package mevcommitclient provides functionality for interacting with the mev-commit protocol.
// It includes interfaces and implementations for querying validator opt-in status,
// monitoring builder events, and validating builder registrations.
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
	GetOptInStatusForValidators(pubkeys []string) ([]bool, error)
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

func NewMevCommitClient(l1MainnetURL, mevCommitURL string, validatorRouterAddress, ProviderRegistryAddress common.Address) (IMevCommitClient, error) {
	l1Client, err := ethclient.Dial(l1MainnetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to L1 Mainnet: %w", err)
	}

	mevCommitClient, err := ethclient.Dial(mevCommitURL)
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
		L1Address:                  l1MainnetURL,
		MevCommitAddress:           mevCommitURL,
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

func (m *MevCommitClient) GetOptInStatusForValidators(pubkeys []string) ([]bool, error) {
	// Get the finalized block number
	currentBlockNumber, err := m.l1Client.BlockNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get current block number: %w", err)
	}

	opts := &bind.CallOpts{
		BlockNumber: big.NewInt(int64(currentBlockNumber - 64)),
	}
	pubkeysBytes := make([][]byte, len(pubkeys))
	for i, pubkey := range pubkeys {
		pubkeysBytes[i] = common.Hex2Bytes(strings.TrimPrefix(pubkey, "0x"))
	}

	optInStatuses, err := m.validatorOptInRouterCaller.AreValidatorsOptedIn(opts, pubkeysBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to get opt-in status: %w", err)
	}

	isOptedIn := make([]bool, len(optInStatuses))
	for i, status := range optInStatuses {
		isOptedIn[i] = status.IsAvsOptedIn || status.IsVanillaOptedIn || status.IsMiddlewareOptedIn
	}

	return isOptedIn, nil
}

func (m *MevCommitClient) ListenForBuildersEvents() (<-chan MevCommitProvider, <-chan common.Address, error) {
	latestBlock, err := m.mevCommitClient.BlockNumber(context.Background())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get latest block number from mev-commit-geth: %w", err)
	}
	filterOpts := &bind.FilterOpts{
		Start:   0,
		End:     &latestBlock,
		Context: context.Background(),
	}
	watchOpts := &bind.WatchOpts{
		Start:   &latestBlock,
		Context: context.Background(),
	}
	builderRegistryEventCh := make(chan MevCommitProvider)
	builderUnregisteredEventCh := make(chan common.Address)

	providerRegisteredIterator, err := m.builderRegistryFilterer.FilterBLSKeyAdded(filterOpts, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to filter ProviderRegistered events: %w", err)
	}

	providerRegisteredEventCh := make(chan *providerRegistry.ProviderregistryBLSKeyAdded)
	providerRegisteredSub, err := m.builderRegistryFilterer.WatchBLSKeyAdded(watchOpts, providerRegisteredEventCh, nil)
	if err != nil {
		providerRegisteredIterator.Close()
		return nil, nil, fmt.Errorf("failed to watch ProviderRegistered events: %w", err)
	}

	providerSlashedIterator, err := m.builderRegistryFilterer.FilterFundsSlashed(filterOpts, nil)
	if err != nil {
		providerRegisteredIterator.Close()
		providerRegisteredSub.Unsubscribe()
		return nil, nil, fmt.Errorf("failed to filter FundsSlashed events: %w", err)
	}

	providerSlashedEventCh := make(chan *providerRegistry.ProviderregistryFundsSlashed)
	providerSlashedSub, err := m.builderRegistryFilterer.WatchFundsSlashed(watchOpts, providerSlashedEventCh, nil)
	if err != nil {
		providerRegisteredIterator.Close()
		providerSlashedIterator.Close()
		providerRegisteredSub.Unsubscribe()
		return nil, nil, fmt.Errorf("failed to watch ProviderSlashed events: %w", err)
	}

	go func() {
		defer providerRegisteredIterator.Close()
		defer providerRegisteredSub.Unsubscribe()

		for providerRegisteredIterator.Next() {
			event := providerRegisteredIterator.Event
			builderRegistryEventCh <- MevCommitProvider{
				Pubkey:     event.BlsPublicKey,
				EOAAddress: event.Provider,
			}
		}
		if err := providerRegisteredIterator.Error(); err != nil {
			fmt.Printf("error while iterating ProviderRegistered events: %v\n", err)
		}

		for {
			select {
			case err := <-providerRegisteredSub.Err():
				fmt.Printf("error in ProviderRegistered subscription: %v\n", err)
				close(builderRegistryEventCh)
				return
			case event := <-providerRegisteredEventCh:
				builderRegistryEventCh <- MevCommitProvider{
					Pubkey:     event.BlsPublicKey,
					EOAAddress: event.Provider,
				}
			}
		}
	}()

	go func() {
		defer providerSlashedSub.Unsubscribe()
		defer providerSlashedIterator.Close()

		for providerSlashedIterator.Next() {
			event := providerSlashedIterator.Event
			isValid, err := m.IsBuilderValid(event.Provider)
			if err != nil {
				fmt.Printf("failed to check if builder is valid: %v\n", err)
				continue
			}
			if !isValid {
				builderUnregisteredEventCh <- event.Provider
			}
		}
		if err := providerSlashedIterator.Error(); err != nil {
			fmt.Printf("error while iterating FundsSlashed events: %v\n", err)
		}

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
