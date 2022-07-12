package api

import (
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

type BuilderGetValidatorsResponseEntry struct {
	Slot  uint64                             `json:"slot,string"`
	Entry *types.SignedValidatorRegistration `json:"entry"`
}

type BuilderSubmitBlockRequestMessage struct {
	Slot                 uint64          `json:"slot,string"`
	ParentHash           types.Hash      `json:"parent_hash" ssz-size:"32"`
	BlockHash            types.Hash      `json:"block_hash" ssz-size:"32"`
	BuilderPubkey        types.PublicKey `json:"builder_pubkey" ssz-size:"48"`
	ProposerPubkey       types.PublicKey `json:"proposer_pubkey" ssz-size:"48"`
	ProposerFeeRecipient types.Address   `json:"proposer_fee_recipient" ssz-size:"32"`
	Value                types.U256Str   `json:"value" ssz-size:"32"`
}

type BuilderSubmitBlockRequest struct {
	Signature        types.Signature                  `json:"signature"`
	Message          BuilderSubmitBlockRequestMessage `json:"message"`
	ExecutionPayload types.ExecutionPayload           `json:"execution_payload"`
}

func BuilderBlockRequestToSignedBuilderBid(bbr *BuilderSubmitBlockRequest, sk *bls.SecretKey, domain types.Domain) (*types.SignedBuilderBid, error) {
	header, err := PayloadToPayloadHeader(&bbr.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	blsPubKey := bls.PublicKeyFromSecretKey(sk)
	var pubKey types.PublicKey
	pubKey.FromSlice(blsPubKey.Compress())

	builderBid := types.BuilderBid{
		Value:  bbr.Message.Value,
		Header: header,
		Pubkey: pubKey,
	}

	sig, err := types.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &types.SignedBuilderBid{
		Message:   &builderBid,
		Signature: sig,
	}, nil
}

func PayloadToPayloadHeader(p *types.ExecutionPayload) (*types.ExecutionPayloadHeader, error) {
	_txs := [][]byte{}
	for _, tx := range p.Transactions {
		_tx := []byte(tx)
		_txs = append(_txs, _tx)
	}

	txs := types.Transactions{Transactions: _txs}
	txroot, err := txs.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &types.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		Random:           p.Random,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        types.ExtraData(p.ExtraData),
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: [32]byte(txroot),
	}, nil
}
