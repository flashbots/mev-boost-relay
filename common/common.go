// Package common provides things used by various other components
package common

import (
	"errors"
	"time"

	"github.com/flashbots/go-utils/cli"
)

var (
	ErrServerAlreadyRunning = errors.New("server already running")

	SecondsPerSlot  = uint64(cli.GetEnvInt("SEC_PER_SLOT", 12))
	DurationPerSlot = time.Duration(SecondsPerSlot) * time.Second

	SlotsPerEpoch    = uint64(cli.GetEnvInt("SLOTS_PER_EPOCH", 32))
	DurationPerEpoch = DurationPerSlot * time.Duration(SlotsPerEpoch)
)

// HTTPServerTimeouts are various timeouts for requests to the mev-boost HTTP server
type HTTPServerTimeouts struct {
	Read       time.Duration // Timeout for body reads. None if 0.
	ReadHeader time.Duration // Timeout for header reads. None if 0.
	Write      time.Duration // Timeout for writes. None if 0.
	Idle       time.Duration // Timeout to disconnect idle client connections. None if 0.
}
