package database

import (
	"encoding/json"
	"time"

	"github.com/flashbots/boost-relay/common"
	"github.com/flashbots/go-boost-utils/types"
)

type ValidatorRegistrationEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Pubkey       string `db:"pubkey"`
	FeeRecipient string `db:"fee_recipient"`
	Timestamp    uint64 `db:"timestamp"`
	GasLimit     uint64 `db:"gas_limit"`
	Signature    string `db:"signature"`
}

type DeliveredPayloadEntry struct {
	ID         uint64    `db:"id"`
	InsertedAt time.Time `db:"inserted_at"`

	Slot  uint64 `db:"slot"`
	Epoch uint64 `db:"epoch"`

	ExecutionPayload         string `db:"execution_payload"`
	SignedBidTrace           string `db:"signed_bid_trace"`
	SignedBuilderBid         string `db:"signed_builder_bid"`
	SignedBlindedBeaconBlock string `db:"signed_blinded_beacon_block"`

	BuilderPubkey        string `db:"builder_pubkey"`
	ProposerPubkey       string `db:"proposer_pubkey"`
	ProposerFeeRecipient string `db:"proposer_fee_recipient"`

	ParentHash  string `db:"parent_hash"`
	BlockHash   string `db:"block_hash"`
	BlockNumber uint64 `db:"block_number"`
	NumTx       int    `db:"num_tx"`
	Value       string `db:"value"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`
}

func NewDeliveredPayloadEntry(bid *types.SignedBuilderBid, signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, payload *types.ExecutionPayload, signedBidTrace *types.SignedBidTrace) (*DeliveredPayloadEntry, error) {
	_bid, err := json.Marshal(bid)
	if err != nil {
		return nil, err
	}

	_signedBlindedBeaconBlock, err := json.Marshal(signedBlindedBeaconBlock)
	if err != nil {
		return nil, err
	}

	_payload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	_trace, err := json.Marshal(signedBidTrace)
	if err != nil {
		return nil, err
	}

	return &DeliveredPayloadEntry{
		Slot:  signedBlindedBeaconBlock.Message.Slot,
		Epoch: signedBlindedBeaconBlock.Message.Slot / uint64(common.SlotsPerEpoch),

		BuilderPubkey:        signedBidTrace.Message.BuilderPubkey.String(),
		ProposerPubkey:       signedBidTrace.Message.ProposerPubkey.String(),
		ProposerFeeRecipient: signedBidTrace.Message.ProposerFeeRecipient.String(),

		ParentHash:  payload.ParentHash.String(),
		BlockHash:   payload.BlockHash.String(),
		BlockNumber: payload.BlockNumber,
		NumTx:       len(payload.Transactions),
		Value:       bid.Message.Value.String(),

		GasUsed:  payload.GasUsed,
		GasLimit: payload.GasLimit,

		ExecutionPayload:         string(_payload),
		SignedBidTrace:           string(_trace),
		SignedBuilderBid:         string(_bid),
		SignedBlindedBeaconBlock: string(_signedBlindedBeaconBlock),
	}, nil
}

type BuilderBlockEntry struct {
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
	NumTx       int    `db:"num_tx"`
	Value       string `db:"value"`

	GasUsed  uint64 `db:"gas_used"`
	GasLimit uint64 `db:"gas_limit"`

	Payload string `db:"payload"`
}

func NewBuilderBlockEntry(payload *types.BuilderSubmitBlockRequest) (*BuilderBlockEntry, error) {
	_payload, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	return &BuilderBlockEntry{
		Slot:  payload.Message.Slot,
		Epoch: payload.Message.Slot / uint64(common.SlotsPerEpoch),

		BuilderPubkey:        payload.Message.BuilderPubkey.String(),
		ProposerPubkey:       payload.Message.ProposerPubkey.String(),
		ProposerFeeRecipient: payload.Message.ProposerFeeRecipient.String(),

		ParentHash:  payload.ExecutionPayload.ParentHash.String(),
		BlockHash:   payload.ExecutionPayload.BlockHash.String(),
		BlockNumber: payload.ExecutionPayload.BlockNumber,
		NumTx:       len(payload.ExecutionPayload.Transactions),
		Value:       payload.Message.Value.String(),

		GasUsed:  payload.ExecutionPayload.GasUsed,
		GasLimit: payload.ExecutionPayload.GasLimit,

		Payload: string(_payload),
	}, nil
}
