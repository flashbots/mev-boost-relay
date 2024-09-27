package mevcommitclient

import (
	"context"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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
		l1Client:                   l1Client,
		mevCommitClient:            mevCommitClient,
		contractAbi:                contractAbi,
	}, nil
}

func (m *MevCommitClient) GetOptInStatusForValidators(pubkeys [][]byte) ([]bool, error) {
	return m.validatorOptInRouterCaller.AreValidatorsOptedIn(nil, pubkeys)
}
func (m *MevCommitClient) GetActiveBuilders() ([]common.Address, error) {
	latestBlock, err := m.mevCommitClient.BlockNumber(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get latest block number: %w", err)
	}

	query := ethereum.FilterQuery{
		FromBlock: big.NewInt(0),
		ToBlock:   big.NewInt(int64(latestBlock)),
		Addresses: []common.Address{m.BuilderRegistryAddress},
		Topics:    [][]common.Hash{{m.contractAbi.Events["BuilderRegistered"].ID}},
	}

	logs, err := m.mevCommitClient.FilterLogs(context.Background(), query)
	if err != nil {
		return nil, fmt.Errorf("failed to filter logs: %w", err)
	}

	activeBuilders := make([]common.Address, 0)
	for _, vLog := range logs {
		builderAddress := common.HexToAddress(vLog.Topics[1].Hex())
		if m.isBuilderValid(builderAddress) {
			activeBuilders = append(activeBuilders, builderAddress)
		}
	}

	return activeBuilders, nil
}

func (m *MevCommitClient) parseBuilderRegisteredEvent(vLog types.Log) (BuilderRegisteredEvent, error) {
	var event BuilderRegisteredEvent
	err := m.contractAbi.UnpackIntoInterface(&event, "BuilderRegistered", vLog.Data)
	if err != nil {
		return event, err
	}
	event.Builder = common.HexToAddress(vLog.Topics[1].Hex())
	event.BlockNumber = vLog.BlockNumber
	event.TxHash = vLog.TxHash

	block, err := m.mevCommitClient.BlockByNumber(context.Background(), big.NewInt(int64(vLog.BlockNumber)))
	if err != nil {
		return event, fmt.Errorf("failed to fetch block %d: %w", vLog.BlockNumber, err)
	}

	event.Timestamp = time.Unix(int64(block.Time()), 0)
	event.IsValid = m.isBuilderValid(event.Builder)

	return event, nil
}

func (m *MevCommitClient) isBuilderValid(builderAddress common.Address) bool {
	err := m.builderRegistryCaller.IsProviderValid(nil, builderAddress)
	return err == nil
}
