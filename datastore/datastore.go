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

	// Database only
	SaveEpochSummary() error
	IncEpochSummaryVal(epoch uint64, field string, value int64) (newVal int64, err error)
	SetEpochSummaryVal(epoch uint64, field string, value int64) (err error)
	SetNXEpochSummaryVal(epoch uint64, field string, value int64) (err error)
	// IncSlotSummaryVal(epoch uint64, key string, value any) error
}

type EpochSummary struct {
	Epoch uint64 `json:"epoch"      db:"epoch"`

	// first and last slots are just derived from the epoch
	FirstSlot uint64 `json:"slot_first" db:"slot_first"`
	LastSlot  uint64 `json:"slot_last"  db:"slot_last"`

	// registered are those that were actually used by the relay (some might be skipped if only one relay and it started in the mmiddle of the epoch)
	FirstSlotProcessed uint64 `json:"slot_first_processed" db:"slot_first_processed"`
	LastSlotProcessed  uint64 `json:"slot_last_processed"  db:"slot_last_processed"`

	// Validator stats
	ValidatorsKnownTotal                     uint64 `json:"validators_known_total"                      db:"validators_known_total"`
	ValidatorRegistrationsTotal              uint64 `json:"validator_registrations_total"               db:"validator_registrations_total"`
	ValidatorRegistrationsSaved              uint64 `json:"validator_registrations_saved"               db:"validator_registrations_saved"`
	ValidatorRegistrationsReceviedUnverified uint64 `json:"validator_registrations_received_unverified" db:"validator_registrations_received_unverified"`

	// The number of requests are the count of all requests to a specific path, even invalid ones
	NumRegisterValidatorRequests uint64 `json:"num_register_validator_requests" db:"num_register_validator_requests"`
	NumGetHeaderRequests         uint64 `json:"num_get_header_requests"         db:"num_get_header_requests"`
	NumGetPayloadRequests        uint64 `json:"num_get_payload_requests"        db:"num_get_payload_requests"`

	// Responses to successful queries
	NumHeaderSentOk       uint64 `json:"num_header_sent_ok"       db:"num_header_sent_ok"`
	NumHeaderSent204      uint64 `json:"num_header_sent_204"      db:"num_header_sent_204"`
	NumPayloadSent        uint64 `json:"num_payload_sent"         db:"num_payload_sent"`
	NumBuilderBidReceived uint64 `json:"num_builder_bid_received" db:"num_builder_bid_received"`
}
