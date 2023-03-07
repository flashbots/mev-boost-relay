package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flashbots/go-utils/cli"
	"github.com/flashbots/go-utils/jsonrpc"
)

var (
	ErrRequestClosed    = errors.New("request context closed")
	ErrSimulationFailed = errors.New("simulation failed")

	maxConcurrentBlocks = int64(cli.GetEnvInt("BLOCKSIM_MAX_CONCURRENT", 4)) // 0 for no maximum
	simRequestTimeout   = time.Duration(cli.GetEnvInt("BLOCKSIM_TIMEOUT_MS", 10000)) * time.Millisecond
)

type IBlockSimRateLimiter interface {
	send(context context.Context, payload *BuilderBlockValidationRequest, isHighPrio bool) error
	currentCounter() int64
}

type BlockSimulationRateLimiter struct {
	cv          *sync.Cond
	counter     int64
	blockSimURL string
	client      http.Client
}

func NewBlockSimulationRateLimiter(blockSimURL string) *BlockSimulationRateLimiter {
	return &BlockSimulationRateLimiter{
		cv:          sync.NewCond(&sync.Mutex{}),
		counter:     0,
		blockSimURL: blockSimURL,
		client: http.Client{ //nolint:exhaustruct
			Timeout: simRequestTimeout,
		},
	}
}

func (b *BlockSimulationRateLimiter) send(context context.Context, payload *BuilderBlockValidationRequest, isHighPrio bool) error {
	b.cv.L.Lock()
	cnt := atomic.AddInt64(&b.counter, 1)
	if maxConcurrentBlocks > 0 && cnt > maxConcurrentBlocks {
		b.cv.Wait()
	}
	b.cv.L.Unlock()

	defer func() {
		b.cv.L.Lock()
		atomic.AddInt64(&b.counter, -1)
		b.cv.Signal()
		b.cv.L.Unlock()
	}()

	if err := context.Err(); err != nil {
		return ErrRequestClosed
	}

	var simReq *jsonrpc.JSONRPCRequest
	var simResp *jsonrpc.JSONRPCResponse
	var err error
	if payload.Bellatrix != nil {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV1", payload)
		simResp, err = SendJSONRPCRequest(&b.client, *simReq, b.blockSimURL, isHighPrio)
	}

	if payload.Capella != nil {
		simReq = jsonrpc.NewJSONRPCRequest("1", "flashbots_validateBuilderSubmissionV2", payload)
		simResp, err = SendJSONRPCRequest(&b.client, *simReq, b.blockSimURL, isHighPrio)
	}

	if err != nil {
		return err
	} else if simResp.Error != nil {
		return fmt.Errorf("%w: %s", ErrSimulationFailed, simResp.Error.Message)
	}
	return nil
}

// currentCounter returns the number of waiting and active requests
func (b *BlockSimulationRateLimiter) currentCounter() int64 {
	return atomic.LoadInt64(&b.counter)
}

// SendJSONRPCRequest sends the request to URL and returns the general JsonRpcResponse, or an error (note: not the JSONRPCError)
func SendJSONRPCRequest(client *http.Client, req jsonrpc.JSONRPCRequest, url string, isHighPrio bool) (res *jsonrpc.JSONRPCResponse, err error) {
	buf, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}

	// set request headers
	httpReq.Header.Add("Content-Type", "application/json")
	if isHighPrio {
		httpReq.Header.Add("X-High-Priority", "true")
	}

	// execute request
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// read all resp bytes
	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read response bytes: %w", err)
	}

	// try json parsing
	res = new(jsonrpc.JSONRPCResponse)
	if err := json.NewDecoder(bytes.NewReader(rawResp)).Decode(res); err != nil {
		// JSON parsing didn't work, return *jsonrpc.JSONRPCResponse with full response for debugging
		res.Error = &jsonrpc.JSONRPCError{
			Message: fmt.Errorf("unable to parse json: %w, full message: %v", err, rawResp).Error(),
		}
	}

	return res, nil
}
