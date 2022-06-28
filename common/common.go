// Package common provides things used by various other components
package common

import (
	"errors"
	"time"
)

var (
	ErrServerAlreadyRunning = errors.New("server already running")

	SlotsPerEpoch    = 32
	DurationPerSlot  = time.Second * 12
	DurationPerEpoch = DurationPerSlot * time.Duration(SlotsPerEpoch)
)

// HTTPServerTimeouts are various timeouts for requests to the mev-boost HTTP server
type HTTPServerTimeouts struct {
	Read       time.Duration // Timeout for body reads. None if 0.
	ReadHeader time.Duration // Timeout for header reads. None if 0.
	Write      time.Duration // Timeout for writes. None if 0.
	Idle       time.Duration // Timeout to disconnect idle client connections. None if 0.
}
