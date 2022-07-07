// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"github.com/flashbots/go-boost-utils/types"
)

type ProposerDatastore interface {
	IsKnownValidator(pubkeyHex types.PubkeyHex) bool
	RefreshKnownValidators() (cnt int, err error)

	GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error)

	// GetValidatorRegistrationTimestamp returns the timestamp of a previous registration. If none found, timestamp is 0 and err is nil.
	GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error)

	SetValidatorRegistration(entry types.SignedValidatorRegistration) error
	UpdateValidatorRegistration(entry types.SignedValidatorRegistration) (wasUpdated bool, err error)
}
