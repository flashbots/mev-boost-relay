package api

import (
	"errors"

	boostTypes "github.com/flashbots/go-boost-utils/types"
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
