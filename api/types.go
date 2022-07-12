package api

import (
	"errors"

	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/types"
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

var NilResponse = struct{}{}

var VersionBellatrix = "bellatrix"

var ZeroU256 = types.IntToU256(0)

func BuilderSubmitBlockRequestToSignedBuilderBid(req *types.BuilderSubmitBlockRequest, sk *bls.SecretKey, pubkey *types.PublicKey, domain types.Domain) (*types.SignedBuilderBid, error) {
	if req == nil {
		return nil, errors.New("req is nil")
	}

	if sk == nil {
		return nil, errors.New("secret key is nil")
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

type StatusHtmlData struct {
	Pubkey               string
	ValidatorsStats      string
	GenesisForkVersion   string
	BuilderSigningDomain string
	Header               string
	Block                string
}
