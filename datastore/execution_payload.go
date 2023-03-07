package datastore

import "github.com/flashbots/mev-boost-relay/common"

type ExecutionPayloadRepository interface {
	GetExecutionPayload(slot uint64, proposerPubKey, blockHash string) (*common.VersionedExecutionPayload, error)
	SaveExecutionPayload(slot uint64, proposerPubKey, blockHash string, payload *common.GetPayloadResponse) error
}
