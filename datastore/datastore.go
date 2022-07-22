// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"github.com/flashbots/go-boost-utils/types"
)

type BidKey struct {
	Slot           uint64
	ParentHash     string
	ProposerPubkey string
}

type BlockKey struct {
	Slot           uint64
	ProposerPubkey string
	BlockHash      string
}

type Datastore interface {
	RefreshKnownValidators() (cnt int, err error) // Updates local cache of known validators
	IsKnownValidator(pubkeyHex types.PubkeyHex) bool
	GetKnownValidatorPubkeyByIndex(index uint64) (types.PubkeyHex, bool)
	NumKnownValidators() int
	NumRegisteredValidators() (int64, error)

	GetValidatorRegistration(pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error)

	// GetValidatorRegistrationTimestamp returns the timestamp of a previous registration. If none found, timestamp is 0 and err is nil.
	GetValidatorRegistrationTimestamp(pubkeyHex types.PubkeyHex) (uint64, error)

	SetValidatorRegistration(entry types.SignedValidatorRegistration) error

	GetBid(slot uint64, parentHash string, proposerPubkeyHex string) (*types.GetHeaderResponse, error)
	GetBlock(slot uint64, proposerPubkey string, blockHash string) (*types.GetPayloadResponse, error)
	SaveBidAndBlock(slot uint64, proposerPubkey string, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error
	CleanupOldBidsAndBlocks(slot uint64) (numRemoved int, numRemaining int)

	// Keeping track of delivered payloads
	SetSlotPayloadDelivered(slot uint64, proposerPubkey string, blockhash string) (err error)

	// Epoch summary (with error logging)
	IncEpochSummaryVal(epoch uint64, field string, value int64) (newVal int64, err error)
	SetEpochSummaryVal(epoch uint64, field string, value int64) (err error)
	SetNXEpochSummaryVal(epoch uint64, field string, value int64) (err error)

	// Slot summary (with error logging)
	IncSlotSummaryVal(slot uint64, field string, value int64) (newVal int64, err error)
	SetSlotSummaryVal(slot uint64, field string, value int64) (err error)
	SetNXSlotSummaryVal(slot uint64, field string, value int64) (err error)
}
