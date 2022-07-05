// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"github.com/flashbots/go-boost-utils/types"
)

type ProposerDatastore interface {
	GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error)
	SaveValidatorRegistration(entry types.SignedValidatorRegistration) error
	SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error

	SetKnownValidator(pubkeyHex string) error
	IsKnownValidator(pubkeyHex string) (bool, error)
}
