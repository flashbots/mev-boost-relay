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

	NilResponse = struct{}{}
	ZeroU256    = boostTypes.IntToU256(0)
)

type HTTPErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type HTTPMessageResp struct {
	Message string `json:"message"`
}
