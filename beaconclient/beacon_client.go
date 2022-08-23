// Package beaconclient provides a beacon-node client
package beaconclient

import "github.com/flashbots/go-boost-utils/types"

type BeaconNodeClient interface {
	SyncStatus() (*SyncStatusPayloadData, error)
	CurrentSlot() (uint64, error)
	SubscribeToHeadEvents(slotC chan HeadEventData)
	FetchValidators() (map[types.PubkeyHex]ValidatorResponseEntry, error)
	GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error)
}
