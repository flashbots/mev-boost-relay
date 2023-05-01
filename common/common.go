// Package common provides things used by various other components
package common

import (
	"errors"
	"fmt"
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

// BuilderStatus configures how builder blocks are processed.
type BuilderStatus struct {
	IsHighPrio    bool
	IsBlacklisted bool
	IsOptimistic  bool
}

// Profile captures performance metrics for the block submission handler. Each
// field corresponds to the number of microseconds in each stage. The `Total`
// field is the number of microseconds taken for entire flow.
type Profile struct {
	Decode      uint64
	Prechecks   uint64
	Simulation  uint64
	RedisUpdate uint64
	Total       uint64
}

func (p *Profile) String() string {
	return fmt.Sprintf("%v,%v,%v,%v,%v", p.Decode, p.Prechecks, p.Simulation, p.RedisUpdate, p.Total)
}
