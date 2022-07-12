package api

import (
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

var VersionBellatrix = "bellatrix"
