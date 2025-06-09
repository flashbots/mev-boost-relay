package common

import (
	"fmt"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	dynamicssz "github.com/pk910/dynamic-ssz"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	ErrSSZManagerNotInitialized = errors.New("SSZ manager not initialized")
	ErrInvalidSpecConfig        = errors.New("invalid spec config")
)

// HashRootObject represents an object that can compute its hash tree root
type HashRootObject interface {
	HashTreeRoot() ([32]byte, error)
}

// SSZManager manages dynamic SSZ operations with a single initialized instance
type SSZManager struct {
	mu     sync.RWMutex
	dynSSZ *dynamicssz.DynSsz
	config map[string]interface{}
	log    *logrus.Entry
}

// NewSSZManager creates a new SSZ manager
func NewSSZManager(log *logrus.Entry) *SSZManager {
	return &SSZManager{
		log: log,
	}
}

// Initialize sets up the dynamic SSZ library with the provided beacon config
func (m *SSZManager) Initialize(beaconConfig map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if beaconConfig == nil {
		return ErrInvalidSpecConfig
	}

	m.config = beaconConfig

	// Create dynamic SSZ instance with config - it will handle minimal vs mainnet detection internally
	m.dynSSZ = dynamicssz.NewDynSsz(beaconConfig)

	m.log.WithFields(logrus.Fields{
		"configKeys": len(beaconConfig),
	}).Info("SSZ manager initialized")

	return nil
}

// IsInitialized returns whether the SSZ manager has been initialized
func (m *SSZManager) IsInitialized() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dynSSZ != nil
}

// SignMessage signs a message using the appropriate SSZ encoding
// For now, we use standard SSZ for signing since dynamic SSZ doesn't provide hash tree root functionality
func (m *SSZManager) SignMessage(obj HashRootObject, domain phase0.Domain, secretKey *bls.SecretKey) (phase0.BLSSignature, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.dynSSZ == nil {
		return phase0.BLSSignature{}, ErrSSZManagerNotInitialized
	}

	// For now, always use standard SSZ for signing until we have hash tree root support in dynamic SSZ
	return ssz.SignMessage(obj, domain, secretKey)
}

// MarshalSSZ marshals an object using the appropriate SSZ encoding
func (m *SSZManager) MarshalSSZ(obj interface{}) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.dynSSZ == nil {
		return nil, ErrSSZManagerNotInitialized
	}

	// Try dynamic SSZ first - it will automatically fall back to standard SSZ for mainnet/testnet
	data, err := m.dynSSZ.MarshalSSZ(obj)
	if err == nil {
		return data, nil
	}

	// If dynamic SSZ fails, fall back to standard SSZ
	if sszObj, ok := obj.(interface{ MarshalSSZ() ([]byte, error) }); ok {
		return sszObj.MarshalSSZ()
	}

	return nil, fmt.Errorf("object does not support SSZ marshaling")
}

// UnmarshalSSZ unmarshals data using the appropriate SSZ encoding
func (m *SSZManager) UnmarshalSSZ(obj interface{}, data []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.dynSSZ == nil {
		return ErrSSZManagerNotInitialized
	}

	// Try dynamic SSZ first - it will automatically fall back to standard SSZ for mainnet/testnet
	err := m.dynSSZ.UnmarshalSSZ(obj, data)
	if err == nil {
		return nil
	}

	// If dynamic SSZ fails, fall back to standard SSZ
	if sszObj, ok := obj.(interface{ UnmarshalSSZ([]byte) error }); ok {
		return sszObj.UnmarshalSSZ(data)
	}

	return fmt.Errorf("object does not support SSZ unmarshaling")
}

// HashTreeRoot computes hash tree root using the appropriate SSZ encoding
// For now, always uses standard SSZ since dynamic SSZ doesn't support hash tree root
func (m *SSZManager) HashTreeRoot(obj interface{}) (phase0.Root, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.dynSSZ == nil {
		return phase0.Root{}, ErrSSZManagerNotInitialized
	}

	// For now, always use standard SSZ for hash tree root
	if sszObj, ok := obj.(interface{ HashTreeRoot() ([32]byte, error) }); ok {
		root, err := sszObj.HashTreeRoot()
		if err != nil {
			return phase0.Root{}, err
		}
		return phase0.Root(root), nil
	}

	return phase0.Root{}, fmt.Errorf("object does not support HashTreeRoot")
}

// GetConfig returns a copy of the current beacon config
func (m *SSZManager) GetConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.config == nil {
		return nil
	}

	// Return a deep copy to prevent modification
	configCopy := make(map[string]interface{})
	for k, v := range m.config {
		configCopy[k] = v
	}
	return configCopy
}
