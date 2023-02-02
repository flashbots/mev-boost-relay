package api

import (
	"errors"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/spec"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	gethCommon "github.com/ethereum/go-ethereum/common"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/flashbots/mev-boost-relay/types"
)

var (
	ErrMissingRequest     = errors.New("req is nil")
	ErrMissingSecretKey   = errors.New("secret key is nil")
	ErrEmptyPayload       = errors.New("nil payload")
	ErrInvalidTransaction = errors.New("invalid transaction")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var VersionBellatrix boostTypes.VersionString = "bellatrix"

var ZeroU256 = boostTypes.IntToU256(0)

func BuildGetHeaderResponse(payload *common.BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *boostTypes.PublicKey, domain boostTypes.Domain) (*common.GetHeaderResponse, error) {
	if payload == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	if payload.Bellatrix != nil {
		signedBuilderBid, err := BuilderSubmitBlockRequestToSignedBuilderBid(payload.Bellatrix, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &common.GetHeaderResponse{
			Bellatrix: &boostTypes.GetHeaderResponse{
				Version: VersionBellatrix,
				Data:    signedBuilderBid,
			},
			Capella: nil,
		}, nil
	}

	if payload.Capella != nil {
		signedBuilderBid, err := CapellaBuilderSubmitBlockRequestToSignedBuilderBid(payload.Capella, sk, (*phase0.BLSPubKey)(pubkey), domain)
		if err != nil {
			return nil, err
		}
		return &common.GetHeaderResponse{
			Capella: &spec.VersionedSignedBuilderBid{
				Version:   consensusspec.DataVersionCapella,
				Capella:   signedBuilderBid,
				Bellatrix: nil,
			},
			Bellatrix: nil,
		}, nil
	}
	return nil, ErrEmptyPayload
}

func BuildGetPayloadResponse(payload *common.BuilderSubmitBlockRequest) (*common.GetPayloadResponse, error) {
	if payload.Bellatrix != nil {
		return &common.GetPayloadResponse{
			Bellatrix: &boostTypes.GetPayloadResponse{
				Version: VersionBellatrix,
				Data:    payload.Bellatrix.ExecutionPayload,
			},
			Capella: nil,
		}, nil
	}

	if payload.Capella != nil {
		return &common.GetPayloadResponse{
			Capella: &api.VersionedExecutionPayload{
				Version:   consensusspec.DataVersionCapella,
				Capella:   payload.Capella.ExecutionPayload,
				Bellatrix: nil,
			},
			Bellatrix: nil,
		}, nil
	}

	return nil, ErrEmptyPayload
}

func BuilderSubmitBlockRequestToSignedBuilderBid(req *boostTypes.BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *boostTypes.PublicKey, domain boostTypes.Domain) (*boostTypes.SignedBuilderBid, error) {
	header, err := boostTypes.PayloadToPayloadHeader(req.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := boostTypes.BuilderBid{
		Value:  req.Message.Value,
		Header: header,
		Pubkey: *pubkey,
	}

	sig, err := boostTypes.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &boostTypes.SignedBuilderBid{
		Message:   &builderBid,
		Signature: sig,
	}, nil
}

func CapellaBuilderSubmitBlockRequestToSignedBuilderBid(req *types.CapellaBuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain boostTypes.Domain) (*capella.SignedBuilderBid, error) {
	header, err := CapellaPayloadToPayloadHeader(req.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := capella.BuilderBid{
		Value:  &req.Message.Value,
		Header: header,
		Pubkey: *pubkey,
	}

	sig, err := boostTypes.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &capella.SignedBuilderBid{
		Message:   &builderBid,
		Signature: phase0.BLSSignature(sig),
	}, nil
}

func CapellaPayloadToPayloadHeader(p *consensuscapella.ExecutionPayload) (*consensuscapella.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, ErrEmptyPayload
	}

	transactionData := make([]*gethTypes.Transaction, len(p.Transactions))
	for i, encTx := range p.Transactions {
		var tx gethTypes.Transaction

		if err := tx.UnmarshalBinary(encTx); err != nil {
			return nil, ErrInvalidTransaction
		}
		transactionData[i] = &tx
	}

	withdrawalData := make([]*gethTypes.Withdrawal, len(p.Withdrawals))
	for i, withdrawal := range p.Withdrawals {
		withdrawalData[i] = &gethTypes.Withdrawal{
			Index:     uint64(withdrawal.Index),
			Validator: uint64(withdrawal.ValidatorIndex),
			Address:   gethCommon.Address(withdrawal.Address),
			Amount:    uint64(withdrawal.Amount),
		}
	}

	return &consensuscapella.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		PrevRandao:       p.PrevRandao,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        p.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: phase0.Root(gethTypes.DeriveSha(gethTypes.Transactions(transactionData), trie.NewStackTrie(nil))),
		WithdrawalsRoot:  phase0.Root(gethTypes.DeriveSha(gethTypes.Withdrawals(withdrawalData), trie.NewStackTrie(nil))),
	}, nil
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *common.SignedBeaconBlindedBlock, executionPayload *common.VersionedExecutionPayload) *common.SignedBeaconBlock {
	var signedBeaconBlock common.SignedBeaconBlock
	capellaBlindedBlock := signedBlindedBeaconBlock.Capella
	bellatrixBlindedBlock := signedBlindedBeaconBlock.Bellatrix
	if capellaBlindedBlock != nil {
		signedBeaconBlock.Capella = &consensuscapella.SignedBeaconBlock{
			Signature: capellaBlindedBlock.Signature,
			Message: &consensuscapella.BeaconBlock{
				Slot:          capellaBlindedBlock.Message.Slot,
				ProposerIndex: capellaBlindedBlock.Message.ProposerIndex,
				ParentRoot:    capellaBlindedBlock.Message.ParentRoot,
				StateRoot:     capellaBlindedBlock.Message.StateRoot,
				Body: &consensuscapella.BeaconBlockBody{
					BLSToExecutionChanges: capellaBlindedBlock.Message.Body.BLSToExecutionChanges,
					RANDAOReveal:          capellaBlindedBlock.Message.Body.RANDAOReveal,
					ETH1Data:              capellaBlindedBlock.Message.Body.ETH1Data,
					Graffiti:              capellaBlindedBlock.Message.Body.Graffiti,
					ProposerSlashings:     capellaBlindedBlock.Message.Body.ProposerSlashings,
					AttesterSlashings:     capellaBlindedBlock.Message.Body.AttesterSlashings,
					Attestations:          capellaBlindedBlock.Message.Body.Attestations,
					Deposits:              capellaBlindedBlock.Message.Body.Deposits,
					VoluntaryExits:        capellaBlindedBlock.Message.Body.VoluntaryExits,
					SyncAggregate:         capellaBlindedBlock.Message.Body.SyncAggregate,
					ExecutionPayload:      executionPayload.ExecutionPayload.Capella,
				},
			},
		}
	} else if bellatrixBlindedBlock != nil {
		signedBeaconBlock.Bellatrix = &boostTypes.SignedBeaconBlock{
			Signature: bellatrixBlindedBlock.Signature,
			Message: &boostTypes.BeaconBlock{
				Slot:          bellatrixBlindedBlock.Message.Slot,
				ProposerIndex: bellatrixBlindedBlock.Message.ProposerIndex,
				ParentRoot:    bellatrixBlindedBlock.Message.ParentRoot,
				StateRoot:     bellatrixBlindedBlock.Message.StateRoot,
				Body: &boostTypes.BeaconBlockBody{
					RandaoReveal:      bellatrixBlindedBlock.Message.Body.RandaoReveal,
					Eth1Data:          bellatrixBlindedBlock.Message.Body.Eth1Data,
					Graffiti:          bellatrixBlindedBlock.Message.Body.Graffiti,
					ProposerSlashings: bellatrixBlindedBlock.Message.Body.ProposerSlashings,
					AttesterSlashings: bellatrixBlindedBlock.Message.Body.AttesterSlashings,
					Attestations:      bellatrixBlindedBlock.Message.Body.Attestations,
					Deposits:          bellatrixBlindedBlock.Message.Body.Deposits,
					VoluntaryExits:    bellatrixBlindedBlock.Message.Body.VoluntaryExits,
					SyncAggregate:     bellatrixBlindedBlock.Message.Body.SyncAggregate,
					ExecutionPayload:  executionPayload.ExecutionPayload.Bellatrix,
				},
			},
		}
	}
	return &signedBeaconBlock
}

type BuilderBlockValidationRequest struct {
	common.BuilderSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}
