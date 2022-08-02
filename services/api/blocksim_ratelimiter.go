package api

import (
	"sync"

	"github.com/flashbots/go-utils/cli"
)

var maxConcurrentBlocks = int64(cli.GetEnvInt("BLOCKSIM_MAX_CONCURRENT", 4))

type BlockSimulationRateLimiter struct {
	cv      *sync.Cond
	counter int64
}

func NewBlockSimuationRateLimiter() *BlockSimulationRateLimiter {
	return &BlockSimulationRateLimiter{
		cv:      sync.NewCond(&sync.Mutex{}),
		counter: 0,
	}
}

func (b *BlockSimulationRateLimiter) send(cb func()) {
	b.cv.L.Lock()
	b.counter += 1
	if b.counter > maxConcurrentBlocks {
		b.cv.Wait()
	}
	b.cv.L.Unlock()

	cb()

	b.cv.L.Lock()
	b.counter -= 1
	b.cv.Signal()
	b.cv.L.Unlock()
}
