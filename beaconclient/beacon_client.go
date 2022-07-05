// Package beaconclient provides a beacon-node client
package beaconclient

import "github.com/flashbots/boost-relay/common"

type BeaconNodeClient interface {
	SyncStatus() (*SyncStatusPayloadData, error)
	CurrentSlot() (uint64, error)
	SubscribeToHeadEvents(slotC chan uint64)
	FetchValidators() (map[common.PubkeyHex]ValidatorResponseEntry, error)
}
