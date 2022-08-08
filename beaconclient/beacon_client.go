// Package beaconclient provides a beacon-node client
package beaconclient

import (
	"context"

	"github.com/flashbots/go-boost-utils/types"
)

type BeaconNodeClient interface {
	SyncStatus(ctx context.Context) (*SyncStatusPayloadData, error)
	CurrentSlot(ctx context.Context) (uint64, error)
	SubscribeToHeadEvents(ctx context.Context, slotC chan uint64)
	FetchValidators(ctx context.Context) (map[types.PubkeyHex]ValidatorResponseEntry, error)
	GetProposerDuties(ctx context.Context, epoch uint64) (*ProposerDutiesResponse, error)
}
