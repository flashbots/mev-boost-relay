package database

import (
	"encoding/json"
	"time"

	"github.com/flashbots/go-boost-utils/types"
)

type GetPayloadsFilters struct {
	Slot            uint64
	Cursor          uint64
	Limit           uint64
	BlockHash       string
	BlockNumber     uint64
	IncludeBidTrace bool
	IncludePayloads bool
}

type ValidatorRegistrationEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Pubkey       string `db:"pubkey"`
	FeeRecipient string `db:"fee_recipient"`
	Timestamp    uint64 `db:"timestamp"`
	GasLimit     uint64 `db:"gas_limit"`
	Signature    string `db:"signature"`
}

// type BidTraceEntry struct {
// 	ID         uint64    `db:"id"`
// 	InsertedAt time.Time `db:"inserted_at"`

// 	Slot       uint64 `db:"slot"`
// 	ParentHash string `db:"parent_hash"`
// 	BlockHash  string `db:"block_hash"`

// 	BuilderPubkey        string `db:"builder_pubkey"`
// 	ProposerPubkey       string `db:"proposer_pubkey"`
// 	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

// 	GasUsed  uint64 `db:"gas_used"`
// 	GasLimit uint64 `db:"gas_limit"`

// 	NumTx int    `db:"num_tx"`
// 	Value string `db:"value"`
// }

type ExecutionPayloadEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot           uint64 `db:"slot"`
	ProposerPubkey string `db:"proposer_pubkey"`
	BlockHash      string `db:"block_hash"`

	Version string `db:"version"`
	Payload string `db:"payload"`
}

type BuilderBlockSubmissionEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	// Delivered ExecutionPayload
	ExecutionPayloadID uint64 `db:"execution_payload_id"`

	// Sim Result
	SimSuccess bool   `db:"sim_success"`
	SimError   string `db:"sim_error"`

	// BidTrace data
	Signature string `db:"signature"`

	Slot       uint64 `db:"slot"`
	ParentHash string `db:"parent_hash"`
	BlockHash  string `db:"block_hash"`

	BuilderPubkey        string `db:"builder_pubkey"`
	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`

	NumTx int    `db:"num_tx"`
	Value string `db:"value"`

	// Helpers
	Epoch       uint64 `db:"epoch"`
	BlockNumber uint64 `db:"block_number"`
}

type DeliveredPayloadEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot  uint64 `db:"slot"`
	Epoch uint64 `db:"epoch"`

	BuilderPubkey        string `db:"builder_pubkey"`
	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	ParentHash  string `db:"parent_hash"`
	BlockHash   string `db:"block_hash"`
	BlockNumber uint64 `db:"block_number"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`

	NumTx int    `db:"num_tx"`
	Value string `db:"value"`

	BuilderBlockSubmissionID uint64 `db:"builder_block_submission_id"`
	BuilderBidID             uint64 `db:"builder_bid_id"`

	SignedBlindedBeaconBlock string `db:"signed_blinded_beacon_block"`
}

// func NewDeliveredPayloadEntry(bid *types.SignedBuilderBid, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, payload *types.ExecutionPayload, signedBidTrace *types.SignedBidTrace) (*DeliveredPayloadEntry, error) {
// 	_bid, err := json.Marshal(bid)
// 	if err != nil {
// 		return nil, err
// 	}

// 	_signedBlindedBeaconBlock, err := json.Marshal(signedBlindedBeaconBlock)
// 	if err != nil {
// 		return nil, err
// 	}

// 	_payload, err := json.Marshal(payload)
// 	if err != nil {
// 		return nil, err
// 	}

// 	_trace, err := json.Marshal(signedBidTrace.Message)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &DeliveredPayloadEntry{
// 		Slot:  signedBlindedBeaconBlock.Message.Slot,
// 		Epoch: signedBlindedBeaconBlock.Message.Slot / uint64(common.SlotsPerEpoch),

// 		BuilderPubkey:        signedBidTrace.Message.BuilderPubkey.String(),
// 		ProposerPubkey:       signedBidTrace.Message.ProposerPubkey.String(),
// 		ProposerFeeRecipient: signedBidTrace.Message.ProposerFeeRecipient.String(),

// 		ParentHash:  payload.ParentHash.String(),
// 		BlockHash:   payload.BlockHash.String(),
// 		BlockNumber: payload.BlockNumber,
// 		NumTx:       len(payload.Transactions),
// 		Value:       bid.Message.Value.String(),

// 		GasUsed:  payload.GasUsed,
// 		GasLimit: payload.GasLimit,

// 		ExecutionPayload:         string(_payload),
// 		BidTrace:                 string(_trace),
// 		BidTraceBuilderSig:       signedBidTrace.Signature.String(),
// 		SignedBuilderBid:         string(_bid),
// 		SignedBlindedBeaconBlock: string(_signedBlindedBeaconBlock),
// 	}, nil
// }

// func PayloadToBidTraceEntry(payload *types.BuilderSubmitBlockRequest) *BidTraceEntry {
// 	return &BidTraceEntry{
// 		Slot:       payload.Message.Slot,
// 		ParentHash: payload.ExecutionPayload.ParentHash.String(),
// 		BlockHash:  payload.ExecutionPayload.BlockHash.String(),

// 		BuilderPubkey:        payload.Message.BuilderPubkey.String(),
// 		ProposerPubkey:       payload.Message.ProposerPubkey.String(),
// 		ProposerFeeRecipient: payload.Message.ProposerFeeRecipient.String(),

// 		GasUsed:  payload.Message.GasUsed,
// 		GasLimit: payload.Message.GasLimit,

// 		NumTx: len(payload.ExecutionPayload.Transactions),
// 		Value: payload.Message.Value.String(),
// 	}
// }

func PayloadToExecPayloadEntry(payload *types.BuilderSubmitBlockRequest) (*ExecutionPayloadEntry, error) {
	_payload, err := json.Marshal(payload.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	return &ExecutionPayloadEntry{
		Slot:           payload.Message.Slot,
		ProposerPubkey: payload.Message.ProposerPubkey.String(),
		BlockHash:      payload.ExecutionPayload.BlockHash.String(),

		Version: "bellatrix",
		Payload: string(_payload),
	}, nil
}
