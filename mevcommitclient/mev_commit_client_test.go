package mevcommitclient

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mevCommitRPC             = "https://chainrpc.testnet.mev-commit.xyz/"
	ethereumL1RPC            = "https://ethereum-holesky-rpc.publicnode.com"
	providerRegistryAddr     = "0xf4F10e18244d836311508917A3B04694D88999Dd"
	validatorOptInRouterAddr = "0xCae46e1013D33587180Db5933Abd75D977c2d7ab"
)

func TestNewMevCommitClient(t *testing.T) {
	client, err := NewMevCommitClient(
		ethereumL1RPC,
		mevCommitRPC,
		common.HexToAddress(validatorOptInRouterAddr),
		common.HexToAddress(providerRegistryAddr),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	mevClient, ok := client.(*MevCommitClient)
	require.True(t, ok)

	assert.Equal(t, ethereumL1RPC, mevClient.L1Address)
	assert.Equal(t, mevCommitRPC, mevClient.MevCommitAddress)
	assert.Equal(t, common.HexToAddress(validatorOptInRouterAddr), mevClient.ValidatorRouterAddress)
	assert.Equal(t, common.HexToAddress(providerRegistryAddr), mevClient.ProviderRegistryAddress)
}

func TestGetOptInStatusForValidators(t *testing.T) {
	client, err := NewMevCommitClient(
		ethereumL1RPC,
		mevCommitRPC,
		common.HexToAddress(validatorOptInRouterAddr),
		common.HexToAddress(providerRegistryAddr),
	)
	require.NoError(t, err)

	// Test with some sample public keys
	pubkeys := [][]byte{
		{0x01, 0x02, 0x03},
		{0x04, 0x05, 0x06},
	}

	statuses, err := client.GetOptInStatusForValidators(pubkeys)
	require.NoError(t, err)
	assert.Len(t, statuses, len(pubkeys))

	// Note: The actual values will depend on the state of the contract
	// This test just checks that we get a response without error
	for _, status := range statuses {
		assert.IsType(t, bool(true), status)
	}
}
