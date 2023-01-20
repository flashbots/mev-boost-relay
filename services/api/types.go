package api

import (
	"errors"

	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost-relay/common"
)

var (
	ErrMissingRequest   = errors.New("req is nil")
	ErrMissingSecretKey = errors.New("secret key is nil")
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var VersionBellatrix types.VersionString = "bellatrix"

var ZeroU256 = types.IntToU256(0)

func BuilderSubmitBlockRequestToSignedBuilderBid(req *types.BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *types.PublicKey, domain types.Domain) (*types.SignedBuilderBid, error) {
	if req == nil {
		return nil, ErrMissingRequest
	}

	if sk == nil {
		return nil, ErrMissingSecretKey
	}

	header, err := types.PayloadToPayloadHeader(req.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	builderBid := types.BuilderBid{
		Value:  req.Message.Value,
		Header: header,
		Pubkey: *pubkey,
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

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *common.SignedBeaconBlindedBlock, executionPayload *common.VersionedExecutionPayload) *common.SignedBeaconBlock {
	var signedBeaconBlock common.SignedBeaconBlock
	capellaBlindedBlock := signedBlindedBeaconBlock.Capella
	bellatrixBlindedBlock := signedBlindedBeaconBlock.Bellatrix
	if capellaBlindedBlock != nil {
		signedBeaconBlock.Capella = &capella.SignedBeaconBlock{
			Signature: capellaBlindedBlock.Signature,
			Message: &capella.BeaconBlock{
				Slot:          capellaBlindedBlock.Message.Slot,
				ProposerIndex: capellaBlindedBlock.Message.ProposerIndex,
				ParentRoot:    capellaBlindedBlock.Message.ParentRoot,
				StateRoot:     capellaBlindedBlock.Message.StateRoot,
				Body: &capella.BeaconBlockBody{
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
		signedBeaconBlock.Bellatrix = &types.SignedBeaconBlock{
			Signature: bellatrixBlindedBlock.Signature,
			Message: &types.BeaconBlock{
				Slot:          bellatrixBlindedBlock.Message.Slot,
				ProposerIndex: bellatrixBlindedBlock.Message.ProposerIndex,
				ParentRoot:    bellatrixBlindedBlock.Message.ParentRoot,
				StateRoot:     bellatrixBlindedBlock.Message.StateRoot,
				Body: &types.BeaconBlockBody{
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
	types.BuilderSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}
