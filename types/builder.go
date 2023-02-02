// Package types defines the types used in the relay API
package types

import (
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/holiman/uint256"
)

type CapellaBuilderSubmitBlockRequest struct {
	Signature        phase0.BLSSignature       `json:"signature" ssz-size:"96"`
	Message          *BidTrace                 `json:"message"`
	ExecutionPayload *capella.ExecutionPayload `json:"execution_payload"`
}

type BidTrace struct {
	Slot                 uint64                     `json:"slot,string"`
	ParentHash           phase0.Hash32              `json:"parent_hash" ssz-size:"32"`
	BlockHash            phase0.Hash32              `json:"block_hash" ssz-size:"32"`
	BuilderPubkey        phase0.BLSPubKey           `json:"builder_pubkey" ssz-size:"48"`
	ProposerPubkey       phase0.BLSPubKey           `json:"proposer_pubkey" ssz-size:"48"`
	ProposerFeeRecipient bellatrix.ExecutionAddress `json:"proposer_fee_recipient" ssz-size:"20"`
	GasLimit             uint64                     `json:"gas_limit,string"`
	GasUsed              uint64                     `json:"gas_used,string"`
	Value                uint256.Int                `json:"value" ssz-size:"32"`
}
