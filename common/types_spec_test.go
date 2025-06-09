package common

import (
	"bytes"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/goccy/go-json"
	"github.com/stretchr/testify/require"
)

func TestSubmitBuilderBlockJSON(t *testing.T) {
	jsonBytes := LoadGzippedBytes(t, "../testdata/submitBlockPayloadCapella_Goerli.json.gz")

	submitBlockData := new(VersionedSubmitBlockRequest)
	err := json.Unmarshal(jsonBytes, &submitBlockData)
	require.NoError(t, err)

	marshalledJSONBytes, err := json.Marshal(submitBlockData)
	require.NoError(t, err)
	buffer := new(bytes.Buffer)
	err = json.Compact(buffer, jsonBytes)
	require.NoError(t, err)
	expectedJSONBytes := buffer.Bytes()

	require.JSONEq(t, string(expectedJSONBytes), string(marshalledJSONBytes))
}

func TestSignedBeaconBlockJSON(t *testing.T) {
	testCases := []struct {
		name     string
		filepath string
	}{
		{
			name:     "Capella",
			filepath: "../testdata/signedBeaconBlockCapella_Goerli.json.gz",
		},
		{
			name:     "Deneb",
			filepath: "../testdata/signedBeaconBlockContentsDeneb_Goerli.json.gz",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)
			buffer := new(bytes.Buffer)
			err := json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			expectedJSONBytes := buffer.Bytes()

			blockRequest := new(VersionedSignedProposal)
			err = json.Unmarshal(jsonBytes, blockRequest)
			require.NoError(t, err)

			marshalledJSONBytes, err := json.Marshal(blockRequest)
			require.NoError(t, err)

			require.JSONEq(t, string(expectedJSONBytes), string(marshalledJSONBytes))
		})
	}
}

func TestSignedBlindedBlockJSON(t *testing.T) {
	testCases := []struct {
		name     string
		filepath string
	}{
		{
			name:     "Capella",
			filepath: "../testdata/signedBlindedBeaconBlockCapella_Goerli.json.gz",
		},
		{
			name:     "Deneb",
			filepath: "../testdata/signedBlindedBeaconBlockDeneb_Goerli.json.gz",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)
			buffer := new(bytes.Buffer)
			err := json.Compact(buffer, jsonBytes)
			require.NoError(t, err)
			expectedJSONBytes := buffer.Bytes()

			blockRequest := new(VersionedSignedBlindedBeaconBlock)
			err = json.Unmarshal(jsonBytes, blockRequest)
			require.NoError(t, err)

			marshalledJSONBytes, err := json.Marshal(blockRequest)
			require.NoError(t, err)

			require.JSONEq(t, string(expectedJSONBytes), string(marshalledJSONBytes))
		})
	}
}

func TestBuildGetPayloadResponse(t *testing.T) {
	testCases := []struct {
		name      string
		filepath  string
		version   spec.DataVersion
		blockHash string
	}{
		{
			name:      "Capella",
			filepath:  "../testdata/submitBlockPayloadCapella_Goerli.json.gz",
			version:   spec.DataVersionCapella,
			blockHash: "0x1bafdc454116b605005364976b134d761dd736cb4788d25c835783b46daeb121",
		},
		{
			name:      "Deneb",
			filepath:  "../testdata/submitBlockPayloadDeneb_Goerli.json.gz",
			version:   spec.DataVersionDeneb,
			blockHash: "0x195e2aac0a52cf26428336142e74eafd55d9228f315c2f2fe9253406ef9ef544",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			jsonBytes := LoadGzippedBytes(t, testCase.filepath)

			submitBlockData := new(VersionedSubmitBlockRequest)
			err := json.Unmarshal(jsonBytes, &submitBlockData)
			require.NoError(t, err)

			resp, err := BuildGetPayloadResponse(submitBlockData)
			require.NoError(t, err)

			require.Equal(t, testCase.version, resp.Version)
			blockHash, err := resp.BlockHash()
			require.NoError(t, err)
			require.Equal(t, testCase.blockHash, blockHash.String())
		})
	}
}

// TestStruct implements HashRootObject for testing
type TestStruct struct {
	Value uint64
}

// HashTreeRoot implements the HashRootObject interface
func (t *TestStruct) HashTreeRoot() ([32]byte, error) {
	// Simple mock implementation for testing
	var root [32]byte
	copy(root[:], []byte("test_root_hash_for_testing_123"))
	return root, nil
}

func TestSSZManager_Initialize(t *testing.T) {
	log := TestLog.WithField("test", "SSZManager")

	t.Run("Initialize with minimal spec config", func(t *testing.T) {
		manager := NewSSZManager(log)

		minimalConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "8",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(minimalConfig)
		require.NoError(t, err)
		require.True(t, manager.IsInitialized())

		config := manager.GetConfig()
		require.Equal(t, minimalConfig, config)
	})

	t.Run("Initialize with mainnet config", func(t *testing.T) {
		manager := NewSSZManager(log)

		mainnetConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "32",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(mainnetConfig)
		require.NoError(t, err)
		require.True(t, manager.IsInitialized())

		config := manager.GetConfig()
		require.Equal(t, mainnetConfig, config)
	})

	t.Run("Initialize with nil config", func(t *testing.T) {
		manager := NewSSZManager(log)

		err := manager.Initialize(nil)
		require.Error(t, err)
		require.Equal(t, ErrInvalidSpecConfig, err)
		require.False(t, manager.IsInitialized())
	})
}

func TestSSZManager_SignMessage(t *testing.T) {
	log := TestLog.WithField("test", "SSZManager")

	// Generate test key
	sk, _, err := bls.GenerateNewKeypair()
	require.NoError(t, err)

	// Create test domain
	domain := phase0.Domain{1, 2, 3, 4}

	// Create test struct instance
	testStruct := &TestStruct{Value: 123}

	t.Run("Sign with uninitialized manager", func(t *testing.T) {
		manager := NewSSZManager(log)

		// This should return an error since manager is not initialized
		_, err := manager.SignMessage(testStruct, domain, sk)
		require.Error(t, err)
		require.Equal(t, ErrSSZManagerNotInitialized, err)
	})

	t.Run("Sign with initialized manager", func(t *testing.T) {
		manager := NewSSZManager(log)

		config := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "32",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(config)
		require.NoError(t, err)

		// This should work without error since we use standard SSZ for signing
		_, err = manager.SignMessage(testStruct, domain, sk)
		require.NoError(t, err)
	})
}

func TestSSZManager_MarshalUnmarshal(t *testing.T) {
	log := TestLog.WithField("test", "SSZManager")

	t.Run("MarshalSSZ and UnmarshalSSZ with minimal config", func(t *testing.T) {
		manager := NewSSZManager(log)

		minimalConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "8",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(minimalConfig)
		require.NoError(t, err)

		// Test marshal/unmarshal functionality
		type TestData struct {
			Value uint64
		}

		original := &TestData{Value: 12345}

		// Marshal should not error (even if it falls back to standard SSZ)
		data, err := manager.MarshalSSZ(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Unmarshal should work
		unmarshaled := &TestData{}
		err = manager.UnmarshalSSZ(unmarshaled, data)
		require.NoError(t, err)
		require.Equal(t, original.Value, unmarshaled.Value)
	})

	t.Run("MarshalSSZ and UnmarshalSSZ with mainnet config", func(t *testing.T) {
		manager := NewSSZManager(log)

		mainnetConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "32",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(mainnetConfig)
		require.NoError(t, err)

		// Test marshal/unmarshal functionality
		type TestData struct {
			Value uint64
		}

		original := &TestData{Value: 67890}

		// Marshal should work
		data, err := manager.MarshalSSZ(original)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// Unmarshal should work
		unmarshaled := &TestData{}
		err = manager.UnmarshalSSZ(unmarshaled, data)
		require.NoError(t, err)
		require.Equal(t, original.Value, unmarshaled.Value)
	})
}

func TestSSZManager_HashTreeRoot(t *testing.T) {
	log := TestLog.WithField("test", "SSZManager")

	t.Run("HashTreeRoot with minimal config", func(t *testing.T) {
		manager := NewSSZManager(log)

		minimalConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "8",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(minimalConfig)
		require.NoError(t, err)

		testData := &TestStruct{Value: 12345}

		// HashTreeRoot should work (using standard SSZ)
		root, err := manager.HashTreeRoot(testData)
		require.NoError(t, err)
		require.NotEqual(t, phase0.Root{}, root)
	})

	t.Run("HashTreeRoot with mainnet config", func(t *testing.T) {
		manager := NewSSZManager(log)

		mainnetConfig := map[string]interface{}{
			"SLOTS_PER_EPOCH":  "32",
			"SECONDS_PER_SLOT": "12",
		}

		err := manager.Initialize(mainnetConfig)
		require.NoError(t, err)

		testData := &TestStruct{Value: 67890}

		// HashTreeRoot should work
		root, err := manager.HashTreeRoot(testData)
		require.NoError(t, err)
		require.NotEqual(t, phase0.Root{}, root)
	})
}

func TestSSZManager_ConfigCopy(t *testing.T) {
	log := TestLog.WithField("test", "SSZManager")
	manager := NewSSZManager(log)

	originalConfig := map[string]interface{}{
		"SLOTS_PER_EPOCH":  "8",
		"SECONDS_PER_SLOT": "12",
	}

	err := manager.Initialize(originalConfig)
	require.NoError(t, err)

	// Get config copy
	configCopy := manager.GetConfig()
	require.Equal(t, originalConfig, configCopy)

	// Modify the copy - should not affect original
	configCopy["SLOTS_PER_EPOCH"] = "16"

	// Original config should be unchanged
	configFromManager := manager.GetConfig()
	require.Equal(t, "8", configFromManager["SLOTS_PER_EPOCH"])
}
