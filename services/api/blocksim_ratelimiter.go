package api

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/jsonrpc"
)

var maxConcurrentBlocks = int64(cli.GetEnvInt("BLOCKSIM_MAX_CONCURRENT", 4))

type BlockSimulationRateLimiter struct {
	cv          *sync.Cond
	counter     int64
	blockSimURL string
}

func NewBlockSimulationRateLimiter(blockSimURL string) *BlockSimulationRateLimiter {
	return &BlockSimulationRateLimiter{
		cv:          sync.NewCond(&sync.Mutex{}),
		counter:     0,
		blockSimURL: blockSimURL,
	}
}

func (b *BlockSimulationRateLimiter) send(context context.Context, payload *types.BuilderSubmitBlockRequest) error {
	b.cv.L.Lock()
	b.counter += 1
	if b.counter > maxConcurrentBlocks {
		b.cv.Wait()
	}
	b.cv.L.Unlock()

	defer func() {
		b.cv.L.Lock()
		b.counter -= 1
		b.cv.Signal()
		b.cv.L.Unlock()
	}()

	if err := context.Err(); err != nil {
		return errors.New("request context closed")
	}

	simReq := jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV1", payload)
	simResp, err := jsonrpc.SendJSONRPCRequest(*simReq, b.blockSimURL)
	if err != nil {
		return err
	} else if simResp.Error != nil {
		return fmt.Errorf("simulation failed: %s", simResp.Error.Message)
	}

	return nil
}
