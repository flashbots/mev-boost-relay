package datastore

import (
	"github.com/attestantio/go-builder-client/api"
	"github.com/flashbots/mev-boost-relay/common"
)

// ExecutionPayloadRepository defines methods to fetch and store execution engine payloads
type ExecutionPayloadRepository interface {
	GetExecutionPayload(slot uint64, proposerPubKey, blockHash string) (*api.VersionedExecutionPayload, error)
	SaveExecutionPayload(slot uint64, proposerPubKey, blockHash string, payload *common.GetPayloadResponse) error
}
