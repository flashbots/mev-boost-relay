// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
)

type ProposerDatastore interface {
	GetKnownValidators() (map[common.PubkeyHex]bool, error)
	SetKnownValidator(pubkeyHex common.PubkeyHex) error
	IsKnownValidator(pubkeyHex common.PubkeyHex) (bool, error)

	GetValidatorRegistration(proposerPubkey types.PublicKey) (*types.SignedValidatorRegistration, error)
	SaveValidatorRegistration(entry types.SignedValidatorRegistration) error
	SaveValidatorRegistrations(entries []types.SignedValidatorRegistration) error
}
