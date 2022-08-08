// Package datastore provides redis+DB data stores for the API
package datastore

import (
	"context"

	"github.com/flashbots/boost-relay/database"
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

type BlockBidAndTrace struct {
	Trace   *types.SignedBidTrace
	Bid     *types.GetHeaderResponse
	Payload *types.GetPayloadResponse
}

type Datastore interface {
	RefreshKnownValidators(ctx context.Context) (cnt int, err error) // Updates local cache of known validators
	IsKnownValidator(pubkeyHex types.PubkeyHex) bool
	GetKnownValidatorPubkeyByIndex(index uint64) (types.PubkeyHex, bool)
	NumKnownValidators() int
	NumRegisteredValidators(ctx context.Context) (int64, error)

	GetValidatorRegistration(ctx context.Context, pubkeyHex types.PubkeyHex) (*types.SignedValidatorRegistration, error)

	// GetValidatorRegistrationTimestamp returns the timestamp of a previous registration. If none found, timestamp is 0 and err is nil.
	GetValidatorRegistrationTimestamp(ctx context.Context, pubkeyHex types.PubkeyHex) (uint64, error)

	SetValidatorRegistration(ctx context.Context, entry types.SignedValidatorRegistration) error

	GetBid(slot uint64, parentHash string, proposerPubkeyHex string) (*types.GetHeaderResponse, error)
	GetBlockBidAndTrace(slot uint64, proposerPubkey string, blockHash string) (*BlockBidAndTrace, error)
	SaveBidAndBlock(slot uint64, proposerPubkey string, signedBidTrace *types.SignedBidTrace, headerResp *types.GetHeaderResponse, payloadResp *types.GetPayloadResponse) error
	CleanupOldBidsAndBlocks(slot uint64) (numRemoved int, numRemaining int)

	SaveBuilderBlockSubmission(ctx context.Context, entry *database.BuilderBlockEntry) error
	SaveDeliveredPayload(ctx context.Context, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, bid *types.GetHeaderResponse, payload *types.GetPayloadResponse, signedBidTrace *types.SignedBidTrace) error
	GetRecentDeliveredPayloads(ctx context.Context, filters database.GetPayloadsFilters) ([]*database.DeliveredPayloadEntry, error)

	// // Epoch summary (with error logging)
	// IncEpochSummaryVal(epoch uint64, field string, value int64) (newVal int64, err error)
	// SetEpochSummaryVal(epoch uint64, field string, value int64) (err error)
	// SetNXEpochSummaryVal(epoch uint64, field string, value int64) (err error)

	// // Slot summary (with error logging)
	// IncSlotSummaryVal(slot uint64, field string, value int64) (newVal int64, err error)
	// SetSlotSummaryVal(slot uint64, field string, value int64) (err error)
	// SetNXSlotSummaryVal(slot uint64, field string, value int64) (err error)
}
