package common

import (
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-builder-client/api"
	"github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-builder-client/spec"
	consensusapi "github.com/attestantio/go-eth2-client/api"
	consensusspec "github.com/attestantio/go-eth2-client/spec"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	utilcapella "github.com/attestantio/go-eth2-client/util/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-boost-utils/utils"
	"github.com/pkg/errors"
)

var (
	ErrMissingRequest     = errors.New("req is nil")
	ErrMissingSecretKey   = errors.New("secret key is nil")
	ErrInvalidTransaction = errors.New("invalid transaction")
	ErrInvalidVersion     = errors.New("invalid version")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var ZeroU256 = boostTypes.IntToU256(0)

func BuildGetHeaderResponse(payload *spec.VersionedSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*spec.VersionedSignedBuilderBid, error) {
	if payload == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	if payload.Capella != nil {
		signedBuilderBid, err := CapellaBuilderSubmitBlockRequestToSignedBuilderBid(payload.Capella, sk, pubkey, domain)
		if err != nil {
			return nil, err
		}
		return &spec.VersionedSignedBuilderBid{
			Version:   consensusspec.DataVersionCapella,
			Capella:   signedBuilderBid,
			Bellatrix: nil,
		}, nil
	}
	return nil, ErrEmptyPayload
}

func BuildGetPayloadResponse(payload *spec.VersionedSubmitBlockRequest) (*api.VersionedExecutionPayload, error) {
	if payload.Capella != nil {
		return &api.VersionedExecutionPayload{
			Version: consensusspec.DataVersionCapella,
			Capella: payload.Capella.ExecutionPayload,
		}, nil
	}

	return nil, ErrEmptyPayload
}

func BuilderSubmitBlockRequestToSignedBuilderBid(req *spec.VersionedSubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*spec.VersionedSignedBuilderBid, error) {
	value, err := req.Value()
	if err != nil {
		return nil, err
	}

	switch req.Version {
	case consensusspec.DataVersionCapella:
		header, err := utils.PayloadToPayloadHeader(&api.VersionedExecutionPayload{Version: req.Version, Capella: req.Capella.ExecutionPayload})
		if err != nil {
			return nil, err
		}

		builderBid := capella.BuilderBid{
			Value:  value,
			Header: header.Capella,
			Pubkey: *pubkey,
		}

		sig, err := ssz.SignMessage(&builderBid, domain, sk)
		if err != nil {
			return nil, err
		}

		return &spec.VersionedSignedBuilderBid{
			Version: consensusspec.DataVersionCapella,
			Capella: &capella.SignedBuilderBid{
				Message:   &builderBid,
				Signature: sig,
			},
		}, nil
	case consensusspec.DataVersionUnknown, consensusspec.DataVersionPhase0, consensusspec.DataVersionAltair, consensusspec.DataVersionBellatrix, consensusspec.DataVersionDeneb:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", req.Version.String()))
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%s is not supported", req.Version.String()))
	}
}

func CapellaBuilderSubmitBlockRequestToSignedBuilderBid(req *capella.SubmitBlockRequest, sk *bls.SecretKey, pubkey *phase0.BLSPubKey, domain phase0.Domain) (*capella.SignedBuilderBid, error) {
	header, err := CapellaPayloadToPayloadHeader(req.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := capella.BuilderBid{
		Value:  req.Message.Value,
		Header: header,
		Pubkey: *pubkey,
	}

	sig, err := ssz.SignMessage(&builderBid, domain, sk)
	if err != nil {
		return nil, err
	}

	return &capella.SignedBuilderBid{
		Message:   &builderBid,
		Signature: sig,
	}, nil
}

func CapellaPayloadToPayloadHeader(p *consensuscapella.ExecutionPayload) (*consensuscapella.ExecutionPayloadHeader, error) {
	if p == nil {
		return nil, ErrEmptyPayload
	}

	transactions := utilbellatrix.ExecutionPayloadTransactions{Transactions: p.Transactions}
	transactionsRoot, err := transactions.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	withdrawals := utilcapella.ExecutionPayloadWithdrawals{Withdrawals: p.Withdrawals}
	withdrawalsRoot, err := withdrawals.HashTreeRoot()
	if err != nil {
		return nil, err
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
		TransactionsRoot: transactionsRoot,
		WithdrawalsRoot:  withdrawalsRoot,
	}, nil
}

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *consensusapi.VersionedSignedBlindedBeaconBlock, executionPayload *api.VersionedExecutionPayload) *consensusspec.VersionedSignedBeaconBlock {
	var signedBeaconBlock consensusspec.VersionedSignedBeaconBlock
	capellaBlindedBlock := signedBlindedBeaconBlock.Capella
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
					ExecutionPayload:      executionPayload.Capella,
				},
			},
		}
	}
	return &signedBeaconBlock
}

type BuilderBlockValidationRequest struct {
	spec.VersionedSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BuilderBlockValidationRequest) MarshalJSON() ([]byte, error) {
	var blockRequest []byte
	var err error

	switch r.VersionedSubmitBlockRequest.Version { //nolint:exhaustive
	case consensusspec.DataVersionCapella:
		blockRequest, err = r.VersionedSubmitBlockRequest.Capella.MarshalJSON()
	default:
		return nil, errors.Wrap(ErrInvalidVersion, fmt.Sprintf("%d is not supported", r.VersionedSubmitBlockRequest.Version))
	}
	if err != nil {
		return nil, err
	}
	gasLimit, err := json.Marshal(&struct {
		RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
	}{
		RegisteredGasLimit: r.RegisteredGasLimit,
	})
	if err != nil {
		return nil, err
	}
	gasLimit[0] = ','
	return append(blockRequest[:len(blockRequest)-1], gasLimit...), nil
}
