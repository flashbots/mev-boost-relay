package common

import "errors"

var (
	ErrInvalidSlot      = errors.New("invalid slot")
	ErrInvalidHash      = errors.New("invalid hash")
	ErrInvalidPubkey    = errors.New("invalid pubkey")
	ErrInvalidSignature = errors.New("invalid signature")

	ErrTimestampTooEarly       = errors.New("timestamp too early")
	ErrTimestampTooFarInFuture = errors.New("timestamp too far in the future")
)
