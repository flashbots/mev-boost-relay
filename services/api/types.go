package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
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

func SignedBlindedBeaconBlockToBeaconBlock(signedBlindedBeaconBlock *types.SignedBlindedBeaconBlock, executionPayload *types.ExecutionPayload) *types.SignedBeaconBlock {
	return &types.SignedBeaconBlock{
		Signature: signedBlindedBeaconBlock.Signature,
		Message: &types.BeaconBlock{
			Slot:          signedBlindedBeaconBlock.Message.Slot,
			ProposerIndex: signedBlindedBeaconBlock.Message.ProposerIndex,
			ParentRoot:    signedBlindedBeaconBlock.Message.ParentRoot,
			StateRoot:     signedBlindedBeaconBlock.Message.StateRoot,
			Body: &types.BeaconBlockBody{
				RandaoReveal:      signedBlindedBeaconBlock.Message.Body.RandaoReveal,
				Eth1Data:          signedBlindedBeaconBlock.Message.Body.Eth1Data,
				Graffiti:          signedBlindedBeaconBlock.Message.Body.Graffiti,
				ProposerSlashings: signedBlindedBeaconBlock.Message.Body.ProposerSlashings,
				AttesterSlashings: signedBlindedBeaconBlock.Message.Body.AttesterSlashings,
				Attestations:      signedBlindedBeaconBlock.Message.Body.Attestations,
				Deposits:          signedBlindedBeaconBlock.Message.Body.Deposits,
				VoluntaryExits:    signedBlindedBeaconBlock.Message.Body.VoluntaryExits,
				SyncAggregate:     signedBlindedBeaconBlock.Message.Body.SyncAggregate,
				ExecutionPayload:  executionPayload,
			},
		},
	}
}

type BuilderBlockValidationRequest struct {
	types.BuilderSubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}
