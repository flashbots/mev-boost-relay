// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"github.com/flashbots/go-boost-utils/types"
)

type ProposerDatastore interface {
	IsKnownValidator(pubkeyHex types.PubkeyHex) bool
	RefreshKnownValidators() (cnt int, err error)

	GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error)
	SetValidatorRegistration(entry types.SignedValidatorRegistration) error
	UpdateValidatorRegistration(entry types.SignedValidatorRegistration) (wasUpdated bool, err error)
}
